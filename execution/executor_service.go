package execution

// Este archivo es la fachada de alto nivel de la capa de ejecución que
// usan el nodo, el consenso y la RPC:
//
//   - ExecuteBlock: importa un bloque ajeno (valida cabecera EIP-1559,
//     ejecuta sobre el estado del padre y comprueba raíces).
//   - BuildBlock: el proponente arma un bloque nuevo tomando transacciones
//     de un iterador (el mempool) en orden de precio y nonce.
//   - Call / EstimateGas / CreateAccessList: simulaciones de solo lectura
//     (eth_call, eth_estimateGas, eth_createAccessList).

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/l1/l1/storage"
	"github.com/l1/l1/types"
)

// TxIterator entrega transacciones candidatas en orden de inclusión. Lo
// implementa el mempool.
type TxIterator interface {
	// Peek devuelve la siguiente transacción (nil si no hay más).
	Peek() *types.Transaction
	// Shift acepta la actual y avanza al siguiente nonce de su remitente.
	Shift()
	// Pop descarta la actual y todas las siguientes de su remitente.
	Pop()
}

// SliceTxIterator recorre una lista fija (útil en pruebas y génesis).
type SliceTxIterator struct {
	txs     []*types.Transaction
	dropped map[types.Address]bool
	signer  func(*types.Transaction) (types.Address, error)
}

// NewSliceTxIterator crea un iterador sobre txs (en ese orden).
func NewSliceTxIterator(txs []*types.Transaction, sender func(*types.Transaction) (types.Address, error)) *SliceTxIterator {
	return &SliceTxIterator{txs: txs, dropped: map[types.Address]bool{}, signer: sender}
}

// Peek implementa TxIterator saltando remitentes descartados.
func (it *SliceTxIterator) Peek() *types.Transaction {
	for len(it.txs) > 0 {
		if from, err := it.signer(it.txs[0]); err == nil && !it.dropped[from] {
			return it.txs[0]
		}
		it.txs = it.txs[1:]
	}
	return nil
}

// Shift implementa TxIterator.
func (it *SliceTxIterator) Shift() {
	if len(it.txs) > 0 {
		it.txs = it.txs[1:]
	}
}

// Pop implementa TxIterator.
func (it *SliceTxIterator) Pop() {
	if len(it.txs) > 0 {
		if from, err := it.signer(it.txs[0]); err == nil {
			it.dropped[from] = true
		}
		it.txs = it.txs[1:]
	}
}

// BuildParams son los datos del bloque que fija el proponente/consenso.
type BuildParams struct {
	Coinbase       types.Address
	Timestamp      uint64
	Epoch, View    uint64
	Random         types.Hash
	ExtraData      []byte
	GasLimit       uint64 // objetivo deseado; se acerca respetando 1/1024
	ValidatorsHash types.Hash
	Justify        []byte    // QC del padre (opaco)
	MaxTxs         int       // 0 = sin límite
	Deadline       time.Time // cero = sin límite de tiempo
}

// BuildResult es un bloque recién construido con su ejecución.
type BuildResult struct {
	Block    *types.Block
	Receipts types.Receipts
	State    *storage.StateDB
	Skipped  int // transacciones descartadas durante la construcción
}

// ExecutorService agrupa procesador, base de estado y cadena.
type ExecutorService struct {
	proc  *BlockProcessor
	sdb   *storage.StateDatabase
	chain HeaderByNumberReader
	// RPCGasCap limita el gas de las simulaciones.
	RPCGasCap uint64
	// RPCTimeout limita su duración.
	RPCTimeout time.Duration
}

// NewExecutorService crea el servicio.
func NewExecutorService(proc *BlockProcessor, sdb *storage.StateDatabase, chain HeaderByNumberReader) *ExecutorService {
	return &ExecutorService{proc: proc, sdb: sdb, chain: chain, RPCGasCap: 50_000_000, RPCTimeout: 5 * time.Second}
}

// Processor devuelve el procesador de bloques.
func (s *ExecutorService) Processor() *BlockProcessor { return s.proc }

// StateAt abre el estado con la raíz dada.
func (s *ExecutorService) StateAt(root types.Hash) (*storage.StateDB, error) {
	return storage.New(root, s.sdb)
}

// ExecuteBlock valida y ejecuta un bloque sobre el estado de su padre.
func (s *ExecutorService) ExecuteBlock(block *types.Block, parent *types.Header) (*ProcessResult, *storage.StateDB, error) {
	h := block.HeaderRef()
	if h.ParentHash != parent.Hash() || h.Number != parent.Number+1 {
		return nil, nil, fmt.Errorf("%w: el padre no corresponde", ErrInvalidBlock)
	}
	if err := VerifyEIP1559Header(s.proc.config.Fees, parent, h); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidBlock, err)
	}
	statedb, err := s.StateAt(parent.StateRoot)
	if err != nil {
		return nil, nil, err
	}
	res, err := s.proc.ProcessAndValidate(block, statedb)
	if err != nil {
		return nil, nil, err
	}
	return res, statedb, nil
}

// BuildBlock construye un bloque hijo de parent con transacciones de txs.
func (s *ExecutorService) BuildBlock(parent *types.Header, p BuildParams, txs TxIterator) (*BuildResult, error) {
	statedb, err := s.StateAt(parent.StateRoot)
	if err != nil {
		return nil, err
	}
	desired := p.GasLimit
	if desired == 0 {
		desired = parent.GasLimit
	}
	ts := p.Timestamp
	if ts < parent.Timestamp {
		ts = parent.Timestamp
	}
	header := &types.Header{
		ParentHash: parent.Hash(), Number: parent.Number + 1, Timestamp: ts,
		Proposer: p.Coinbase, GasLimit: CalcGasLimit(parent.GasLimit, desired),
		BaseFee: CalcBaseFee(s.proc.config.Fees, parent), ExtraData: append(types.HexBytes(nil), p.ExtraData...),
		Epoch: p.Epoch, View: p.View, ValidatorsHash: p.ValidatorsHash, Random: p.Random,
	}
	evm := s.proc.NewBlockEVM(header, statedb, s.proc.vmConfig)
	gp := NewGasPool(header.GasLimit)
	var (
		included types.Transactions
		receipts types.Receipts
		usedGas  uint64
		skipped  int
	)
	for txs != nil {
		if p.MaxTxs > 0 && len(included) >= p.MaxTxs {
			break
		}
		if !p.Deadline.IsZero() && time.Now().After(p.Deadline) {
			break
		}
		if gp.Gas() < types.TxGas {
			break // no cabe ni una transferencia
		}
		tx := txs.Peek()
		if tx == nil {
			break
		}
		if tx.Gas > gp.Gas() {
			txs.Pop() // no cabe; las siguientes del remitente tampoco pueden ir
			skipped++
			continue
		}
		snap := statedb.Snapshot()
		gasBefore := gp.Gas()
		r, err := ApplyTransaction(evm, gp, statedb, header, tx, len(included), &usedGas, s.proc.signer)
		switch {
		case err == nil:
			included = append(included, tx)
			receipts = append(receipts, r)
			txs.Shift()
		case errors.Is(err, ErrNonceTooLow):
			// Ya incluida en otro bloque: pasamos a la siguiente del remitente.
			statedb.RevertToSnapshot(snap)
			gp.SetGas(gasBefore)
			txs.Shift()
			skipped++
		default:
			// Nonce futuro, fondos, comisión baja…: se descarta el remitente.
			statedb.RevertToSnapshot(snap)
			gp.SetGas(gasBefore)
			txs.Pop()
			skipped++
		}
	}
	if f := s.proc.finalizer; f != nil {
		if err := f.Finalize(evm, header, p.Justify, statedb, included, receipts); err != nil {
			return nil, fmt.Errorf("finalización: %w", err)
		}
	}
	if err := statedb.Error(); err != nil {
		return nil, err
	}
	header.GasUsed = usedGas
	header.LogsBloom = receipts.Bloom()
	header.ReceiptRoot = storage.DeriveSha(receipts)
	header.StateRoot = statedb.IntermediateRoot(true)
	block, err := types.NewBlockWithRoots(header, included, p.Justify, storage.NewListHasher())
	if err != nil {
		return nil, err
	}
	if err := receipts.DeriveFields(block.Hash(), header.Number, included); err != nil {
		return nil, err
	}
	return &BuildResult{Block: block, Receipts: receipts, State: statedb, Skipped: skipped}, nil
}

// CallArgs son los argumentos de una simulación (estilo eth_call).
type CallArgs struct {
	From       types.Address
	To         *types.Address
	Gas        uint64 // 0 = tope
	GasPrice   *types.Amount
	GasFeeCap  *types.Amount
	GasTipCap  *types.Amount
	Value      types.Amount
	Data       []byte
	AccessList types.AccessList
}

// toMessage convierte los argumentos en un mensaje sin comprobaciones de
// nonce ni EOA. Sin precios explícitos el gas es gratis (NoBaseFee).
func (a *CallArgs) toMessage(statedb StateDB, header *types.Header, gasCap uint64) *Message {
	gas := a.Gas
	if gas == 0 || gas > gasCap {
		gas = gasCap
	}
	msg := &Message{
		From: a.From, To: a.To, Nonce: statedb.GetNonce(a.From), Value: a.Value, GasLimit: gas,
		Data: a.Data, AccessList: a.AccessList, SkipNonceChecks: true, SkipFromEOACheck: true,
	}
	switch {
	case a.GasPrice != nil:
		msg.GasPrice, msg.GasFeeCap, msg.GasTipCap = *a.GasPrice, *a.GasPrice, *a.GasPrice
	case a.GasFeeCap != nil || a.GasTipCap != nil:
		if a.GasFeeCap != nil {
			msg.GasFeeCap = *a.GasFeeCap
		}
		if a.GasTipCap != nil {
			msg.GasTipCap = *a.GasTipCap
		}
		msg.GasPrice = msg.GasFeeCap
		if p := header.BaseFee.Add(msg.GasTipCap); p.Lt(msg.GasFeeCap) {
			msg.GasPrice = p
		}
	}
	return msg
}

// gasCap devuelve el tope de gas de las simulaciones.
func (s *ExecutorService) gasCap(header *types.Header) uint64 {
	c := s.RPCGasCap
	if c == 0 {
		c = math.MaxUint64 / 2
	}
	if header.GasLimit > 0 && header.GasLimit < c {
		c = header.GasLimit
	}
	return c
}

// doCall ejecuta una simulación sobre statedb (que queda modificado).
func (s *ExecutorService) doCall(ctx context.Context, args *CallArgs, header *types.Header, statedb *storage.StateDB, gasLimit uint64, tracer *Hooks) (*ExecutionResult, error) {
	a := *args
	a.Gas = gasLimit
	msg := a.toMessage(statedb, header, s.gasCap(header))
	evm := s.proc.NewBlockEVM(header, statedb, Config{NoBaseFee: true, Tracer: tracer})
	if s.RPCTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.RPCTimeout)
		defer cancel()
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			evm.Cancel() // aborta el intérprete en la siguiente instrucción
		case <-done:
		}
	}()
	res, err := ApplyMessage(evm, msg, NewGasPool(math.MaxUint64))
	if ctx.Err() != nil {
		return nil, fmt.Errorf("simulación abortada: %w", ctx.Err())
	}
	return res, err
}

// Call ejecuta una llamada de solo lectura en el estado de header.
func (s *ExecutorService) Call(ctx context.Context, args CallArgs, header *types.Header) (*ExecutionResult, error) {
	statedb, err := s.StateAt(header.StateRoot)
	if err != nil {
		return nil, err
	}
	return s.doCall(ctx, &args, header, statedb, args.Gas, nil)
}

// EstimateGas busca por bisección el mínimo gasLimit con el que la
// transacción no falla.
func (s *ExecutorService) EstimateGas(ctx context.Context, args CallArgs, header *types.Header) (uint64, error) {
	base, err := s.StateAt(header.StateRoot)
	if err != nil {
		return 0, err
	}
	hi := s.gasCap(header)
	if args.Gas >= types.TxGas && args.Gas < hi {
		hi = args.Gas
	}
	// Con precio explícito, el saldo limita el gas que puede pagarse.
	if price := args.feeCapForBalance(); !price.IsZero() {
		bal := base.GetBalance(args.From)
		if bal.Lt(args.Value) {
			return 0, ErrInsufficientFunds
		}
		allow := bal.Sub(args.Value).Div(price)
		if allow.IsUint64() && allow.Uint64() < hi {
			hi = allow.Uint64()
		}
	}
	// run devuelve (falló, resultado, error fatal).
	run := func(gas uint64) (bool, *ExecutionResult, error) {
		res, err := s.doCall(ctx, &args, header, base.Copy(), gas, nil)
		if err != nil {
			if errors.Is(err, ErrIntrinsicGas) {
				return true, nil, nil
			}
			return true, nil, err
		}
		return res.Failed(), res, nil
	}
	failed, res, err := run(hi)
	if err != nil {
		return 0, err
	}
	if failed {
		if res != nil && res.Err == ErrExecutionReverted {
			return 0, NewRevertError(res.ReturnData)
		}
		if res != nil {
			return 0, fmt.Errorf("la ejecución falla incluso con %d de gas: %w", hi, res.Err)
		}
		return 0, fmt.Errorf("%w con %d de gas", ErrIntrinsicGas, hi)
	}
	// Con menos gas que el pico consumido seguro que falla.
	lo := res.MaxUsedGas - 1
	if lo >= hi {
		return hi, nil
	}
	for lo+1 < hi {
		mid := lo + (hi-lo)/2
		failed, _, err := run(mid)
		if err != nil {
			return 0, err
		}
		if failed {
			lo = mid
		} else {
			hi = mid
		}
	}
	return hi, nil
}

// feeCapForBalance es el precio por gas que se usaría para pagar.
func (a *CallArgs) feeCapForBalance() types.Amount {
	switch {
	case a.GasPrice != nil:
		return *a.GasPrice
	case a.GasFeeCap != nil:
		return *a.GasFeeCap
	}
	return types.Amount{}
}

// AccessListResult es el resultado de CreateAccessList.
type AccessListResult struct {
	AccessList types.AccessList
	GasUsed    uint64
	Err        error // error de la VM con la lista final, si lo hubo
}

// CreateAccessList calcula la lista de acceso de una llamada iterando
// hasta un punto fijo (máximo 8 pasadas).
func (s *ExecutorService) CreateAccessList(ctx context.Context, args CallArgs, header *types.Header) (*AccessListResult, error) {
	base, err := s.StateAt(header.StateRoot)
	if err != nil {
		return nil, err
	}
	excl := []types.Address{args.From, header.Proposer}
	if args.To != nil {
		excl = append(excl, *args.To)
	} else {
		excl = append(excl, types.CreateAddress(args.From, base.GetNonce(args.From)))
	}
	evmTmp := s.proc.NewBlockEVM(header, base, Config{})
	excl = append(excl, evmTmp.ActivePrecompileAddresses()...)

	prev := NewAccessListTracer(args.AccessList, excl)
	for i := 0; i < 8; i++ {
		a := args
		a.AccessList = prev.AccessList()
		tracer := NewAccessListTracer(a.AccessList, excl)
		res, err := s.doCall(ctx, &a, header, base.Copy(), a.Gas, tracer.Hooks())
		if err != nil {
			return nil, err
		}
		if tracer.Equal(prev) {
			return &AccessListResult{AccessList: tracer.AccessList(), GasUsed: res.UsedGas, Err: res.Err}, nil
		}
		prev = tracer
	}
	return nil, errors.New("la lista de acceso no converge")
}
