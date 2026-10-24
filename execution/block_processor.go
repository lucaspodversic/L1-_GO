package execution

// Este archivo ejecuta bloques completos: recupera los remitentes en
// paralelo, aplica las transacciones en orden, ejecuta el gancho de
// finalización del motor de consenso (recompensas, slashing, cambio de
// época…; recibe el QC "justify" del bloque) y, por último, valida que el resultado coincida con los
// compromisos de la cabecera (gas usado, bloom, raíz de recibos y raíz de
// estado).

import (
	"errors"
	"fmt"

	"github.com/l1/l1/crypto"
	"github.com/l1/l1/storage"
	"github.com/l1/l1/types"
)

// Finalizer es el gancho que el motor de consenso ejecuta tras las
// transacciones del bloque y antes de calcular la raíz de estado. Debe ser
// determinista: todos los nodos lo ejecutan igual.
type Finalizer interface {
	Finalize(evm *EVM, header *types.Header, justify []byte, statedb *storage.StateDB, txs types.Transactions, receipts types.Receipts) error
}

// FinalizerFunc adapta una función a Finalizer.
type FinalizerFunc func(evm *EVM, header *types.Header, justify []byte, statedb *storage.StateDB, txs types.Transactions, receipts types.Receipts) error

// Finalize implementa Finalizer.
func (f FinalizerFunc) Finalize(evm *EVM, header *types.Header, justify []byte, statedb *storage.StateDB, txs types.Transactions, receipts types.Receipts) error {
	return f(evm, header, justify, statedb, txs, receipts)
}

// ProcessResult es el resultado de ejecutar un bloque.
type ProcessResult struct {
	Receipts types.Receipts
	Logs     []*types.Log
	GasUsed  uint64
	Bloom    types.Bloom
}

// ErrInvalidBlock envuelve cualquier discrepancia entre la cabecera y la
// ejecución.
var ErrInvalidBlock = errors.New("bloque inválido")

// BlockProcessor ejecuta bloques sobre un StateDB.
type BlockProcessor struct {
	config    *ChainConfig
	chain     HeaderByNumberReader // para BLOCKHASH (puede ser nil)
	vmConfig  Config
	finalizer Finalizer
	signer    crypto.TxSigner
	// Workers es el paralelismo de la recuperación de remitentes.
	Workers int
}

// NewBlockProcessor crea un procesador.
func NewBlockProcessor(config *ChainConfig, chain HeaderByNumberReader, vmConfig Config, finalizer Finalizer) *BlockProcessor {
	if config == nil {
		config = DefaultChainConfig(types.DevnetChainID)
	}
	return &BlockProcessor{config: config, chain: chain, vmConfig: vmConfig, finalizer: finalizer, signer: crypto.NewTxSigner(config.ChainID), Workers: 4}
}

// Config devuelve la configuración de cadena.
func (p *BlockProcessor) Config() *ChainConfig { return p.config }

// Signer devuelve el firmante de transacciones de la cadena.
func (p *BlockProcessor) Signer() crypto.TxSigner { return p.signer }

// NewBlockEVM crea la EVM con el contexto de una cabecera.
func (p *BlockProcessor) NewBlockEVM(header *types.Header, statedb StateDB, cfg Config) *EVM {
	var getHash GetHashFunc
	if p.chain != nil {
		getHash = GetHashFromReader(p.chain)
	}
	return NewEVM(NewEVMBlockContext(header, getHash, nil), TxContext{}, statedb, p.config, cfg)
}

// Process ejecuta todas las transacciones y el finalizador. No valida las
// raíces: eso lo hace ValidateState (para que el constructor de bloques
// pueda reutilizar Process antes de conocerlas).
func (p *BlockProcessor) Process(block *types.Block, statedb *storage.StateDB) (*ProcessResult, error) {
	header := block.Header()
	txs := block.Transactions()
	// Recuperación paralela; los remitentes quedan cacheados en cada tx.
	if _, err := p.signer.RecoverSenders(txs, p.Workers); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidBlock, err)
	}
	var (
		usedGas  uint64
		gp       = NewGasPool(header.GasLimit)
		receipts = make(types.Receipts, 0, len(txs))
		logs     []*types.Log
		evm      = p.NewBlockEVM(header, statedb, p.vmConfig)
	)
	for i, tx := range txs {
		r, err := ApplyTransaction(evm, gp, statedb, header, tx, i, &usedGas, p.signer)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidBlock, err)
		}
		receipts = append(receipts, r)
		logs = append(logs, r.Logs...)
	}
	if p.finalizer != nil {
		if err := p.finalizer.Finalize(evm, header, block.Justify(), statedb, txs, receipts); err != nil {
			return nil, fmt.Errorf("%w: finalización: %v", ErrInvalidBlock, err)
		}
	}
	if err := statedb.Error(); err != nil {
		return nil, err
	}
	// Completamos hash de bloque en recibos y logs.
	if err := receipts.DeriveFields(block.Hash(), header.Number, txs); err != nil {
		return nil, err
	}
	for i, r := range receipts {
		r.EffectiveGasPrice = effectivePrice(txs[i], header.BaseFee)
	}
	return &ProcessResult{Receipts: receipts, Logs: logs, GasUsed: usedGas, Bloom: receipts.Bloom()}, nil
}

// effectivePrice = min(feeCap, baseFee + tipCap).
func effectivePrice(tx *types.Transaction, baseFee types.Amount) types.Amount {
	if p := baseFee.Add(tx.GasTipCap); p.Lt(tx.GasFeeCap) {
		return p
	}
	return tx.GasFeeCap
}

// ValidateState comprueba los compromisos de la cabecera tras ejecutar.
func (p *BlockProcessor) ValidateState(block *types.Block, statedb *storage.StateDB, res *ProcessResult) error {
	h := block.HeaderRef()
	if h.GasUsed != res.GasUsed {
		return fmt.Errorf("%w: %w: cabecera %d, ejecución %d", ErrInvalidBlock, ErrBlockGasUsedMismatch, h.GasUsed, res.GasUsed)
	}
	if h.LogsBloom != res.Bloom {
		return fmt.Errorf("%w: bloom no coincide", ErrInvalidBlock)
	}
	if rr := storage.DeriveSha(res.Receipts); rr != h.ReceiptRoot {
		return fmt.Errorf("%w: raíz de recibos: cabecera %s, ejecución %s", ErrInvalidBlock, h.ReceiptRoot, rr)
	}
	if root := statedb.IntermediateRoot(true); root != h.StateRoot {
		return fmt.Errorf("%w: raíz de estado: cabecera %s, ejecución %s", ErrInvalidBlock, h.StateRoot, root)
	}
	return nil
}

// ProcessAndValidate combina cuerpo, ejecución y validación de estado.
func (p *BlockProcessor) ProcessAndValidate(block *types.Block, statedb *storage.StateDB) (*ProcessResult, error) {
	if err := block.ValidateBody(storage.NewListHasher()); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidBlock, err)
	}
	res, err := p.Process(block, statedb)
	if err != nil {
		return nil, err
	}
	if err := p.ValidateState(block, statedb, res); err != nil {
		return nil, err
	}
	return res, nil
}
