package execution

// Este archivo implementa la transición de estado de una transacción (el
// "modelo de Ethereum" de aplicar un mensaje):
//
//  1. preCheck: nonce correcto, remitente sin código (EOA), máximos de
//     comisión coherentes con la base fee del bloque.
//  2. buyGas: se exige saldo para gasLimit·maxFeePerGas + valor y se cobra
//     por adelantado gasLimit·precioEfectivo; se reserva el gas en el
//     GasPool del bloque.
//  3. Gas intrínseco y comprobaciones de initcode y transferencia.
//  4. Prepare: lista de acceso inicial (EIP-2929/2930/3651) y limpieza del
//     almacenamiento transitorio.
//  5. Ejecución: CREATE o CALL en la EVM.
//  6. Reembolso: hasta gasUsado/5 (EIP-3529); se devuelve el gas sobrante
//     al remitente y al GasPool.
//  7. Comisiones: la propina efectiva va al proponente; la base fee se
//     quema (o va a la tesorería si está configurada).
//
// Los errores devueltos por ApplyMessage invalidan la transacción (no
// entra en el bloque). Los fallos de la VM se reflejan en
// ExecutionResult.Err y la transacción sí se incluye (estado "fallido").

import (
	"fmt"
	"math"

	"github.com/l1/l1/crypto"
	"github.com/l1/l1/types"
)

// Message es una transacción ya "desempaquetada" (con remitente).
type Message struct {
	From       types.Address
	To         *types.Address
	Nonce      uint64
	Value      types.Amount
	GasLimit   uint64
	GasPrice   types.Amount // precio efectivo (baseFee + propina efectiva)
	GasFeeCap  types.Amount
	GasTipCap  types.Amount
	Data       []byte
	AccessList types.AccessList
	// SkipNonceChecks y SkipFromEOACheck relajan la validación en
	// llamadas simuladas (eth_call / eth_estimateGas).
	SkipNonceChecks  bool
	SkipFromEOACheck bool
}

// TransactionToMessage recupera el remitente y calcula el precio efectivo.
func TransactionToMessage(tx *types.Transaction, signer crypto.TxSigner, baseFee types.Amount) (*Message, error) {
	from, err := signer.Sender(tx)
	if err != nil {
		return nil, err
	}
	msg := &Message{
		From: from, To: tx.To, Nonce: tx.Nonce, Value: tx.Value, GasLimit: tx.Gas,
		GasFeeCap: tx.GasFeeCap, GasTipCap: tx.GasTipCap, GasPrice: tx.GasFeeCap,
		Data: tx.Data, AccessList: tx.AccessList,
	}
	// precio = min(feeCap, baseFee + tipCap)
	if p := baseFee.Add(tx.GasTipCap); p.Lt(tx.GasFeeCap) {
		msg.GasPrice = p
	}
	return msg, nil
}

// ExecutionResult es el resultado de aplicar un mensaje.
type ExecutionResult struct {
	UsedGas         uint64 // gas consumido tras el reembolso
	MaxUsedGas      uint64 // gas consumido antes del reembolso (pico)
	RefundedGas     uint64
	Err             error  // error de la VM (nil si tuvo éxito)
	ReturnData      []byte // salida (o datos del revert)
	ContractAddress types.Address
}

// Failed informa si la ejecución falló.
func (r *ExecutionResult) Failed() bool { return r.Err != nil }

// Return devuelve la salida si tuvo éxito.
func (r *ExecutionResult) Return() []byte {
	if r.Err != nil {
		return nil
	}
	return append([]byte(nil), r.ReturnData...)
}

// Revert devuelve los datos del revert si la ejecución revirtió.
func (r *ExecutionResult) Revert() []byte {
	if r.Err != ErrExecutionReverted {
		return nil
	}
	return append([]byte(nil), r.ReturnData...)
}

// stateTransition guarda el estado intermedio de la aplicación.
type stateTransition struct {
	gp           *GasPool
	msg          *Message
	evm          *EVM
	state        StateDB
	initialGas   uint64
	gasRemaining uint64
}

// ApplyMessage aplica msg sobre el estado de evm.
func ApplyMessage(evm *EVM, msg *Message, gp *GasPool) (*ExecutionResult, error) {
	evm.SetTxContext(NewEVMTxContext(msg.From, msg.GasPrice))
	st := &stateTransition{gp: gp, msg: msg, evm: evm, state: evm.StateDB}
	return st.execute()
}

// preCheck valida nonce, EOA y comisiones, y compra el gas.
func (st *stateTransition) preCheck() error {
	msg := st.msg
	if !msg.SkipNonceChecks {
		stNonce := st.state.GetNonce(msg.From)
		switch {
		case stNonce < msg.Nonce:
			return fmt.Errorf("%w: dirección %s, nonce tx %d, nonce estado %d", ErrNonceTooHigh, msg.From, msg.Nonce, stNonce)
		case stNonce > msg.Nonce:
			return fmt.Errorf("%w: dirección %s, nonce tx %d, nonce estado %d", ErrNonceTooLow, msg.From, msg.Nonce, stNonce)
		case stNonce == math.MaxUint64:
			return fmt.Errorf("%w: dirección %s", ErrNonceMax, msg.From)
		}
	}
	if !msg.SkipFromEOACheck {
		// Sólo cuentas sin código pueden originar transacciones (EIP-3607).
		if st.state.GetCodeSize(msg.From) != 0 {
			return fmt.Errorf("%w: %s", ErrSenderNoEOA, msg.From)
		}
	}
	// Con NoBaseFee y precios a cero (simulaciones) no se validan comisiones.
	skipFee := st.evm.Config.NoBaseFee && msg.GasFeeCap.IsZero() && msg.GasTipCap.IsZero()
	if !skipFee {
		if msg.GasFeeCap.Lt(msg.GasTipCap) {
			return fmt.Errorf("%w: tip %s > feeCap %s", ErrTipAboveFeeCap, msg.GasTipCap, msg.GasFeeCap)
		}
		if msg.GasFeeCap.Lt(st.evm.Context.BaseFee) {
			return fmt.Errorf("%w: dirección %s, feeCap %s, baseFee %s", ErrFeeCapTooLow, msg.From, msg.GasFeeCap, st.evm.Context.BaseFee)
		}
	}
	return st.buyGas()
}

// buyGas cobra por adelantado el gas al precio efectivo.
func (st *stateTransition) buyGas() error {
	msg := st.msg
	mgval := msg.GasPrice.MulUint64(msg.GasLimit)
	// El saldo debe cubrir el peor caso: gasLimit · feeCap + valor.
	balanceCheck := msg.GasFeeCap.MulUint64(msg.GasLimit)
	if balanceCheck.Lt(mgval) {
		balanceCheck = mgval
	}
	balanceCheck = balanceCheck.Add(msg.Value)
	if have := st.state.GetBalance(msg.From); have.Lt(balanceCheck) {
		return fmt.Errorf("%w: dirección %s tiene %s, necesita %s", ErrInsufficientFunds, msg.From, have, balanceCheck)
	}
	if err := st.gp.SubGas(msg.GasLimit); err != nil {
		return err
	}
	st.initialGas = msg.GasLimit
	st.gasRemaining = msg.GasLimit
	if err := st.state.SubBalance(msg.From, mgval); err != nil {
		st.gp.AddGas(msg.GasLimit)
		return fmt.Errorf("%w: %v", ErrInsufficientFunds, err)
	}
	return nil
}

// execute realiza la transición completa.
func (st *stateTransition) execute() (*ExecutionResult, error) {
	if err := st.preCheck(); err != nil {
		return nil, err
	}
	msg := st.msg
	rules := st.evm
	contractCreation := msg.To == nil

	// Gas intrínseco.
	gas, err := IntrinsicGas(msg.Data, msg.AccessList, contractCreation)
	if err != nil {
		return nil, err
	}
	if st.gasRemaining < gas {
		return nil, fmt.Errorf("%w: tiene %d, necesita %d", ErrIntrinsicGas, st.gasRemaining, gas)
	}
	st.gasRemaining -= gas

	// Límite de initcode (EIP-3860).
	if contractCreation && uint64(len(msg.Data)) > maxInitCodeSize {
		return nil, fmt.Errorf("%w: %d > %d", ErrInitCodeTooLarge, len(msg.Data), maxInitCodeSize)
	}
	value := WordFromAmount(msg.Value)
	if !value.IsZero() && !st.evm.Context.CanTransfer(st.state, msg.From, value) {
		return nil, fmt.Errorf("%w: dirección %s", ErrInsufficientFunds, msg.From)
	}

	// Lista de acceso inicial y almacenamiento transitorio limpio.
	st.state.Prepare(msg.From, st.evm.Context.Coinbase, msg.To, rules.ActivePrecompileAddresses(), msg.AccessList)

	var (
		ret      []byte
		vmerr    error
		contract types.Address
	)
	if contractCreation {
		ret, contract, st.gasRemaining, vmerr = st.evm.Create(msg.From, msg.Data, st.gasRemaining, value)
	} else {
		// El nonce se incrementa aquí; en CREATE lo incrementa evm.Create.
		st.state.SetNonce(msg.From, st.state.GetNonce(msg.From)+1)
		if IsSimpleTransfer(st.evm, &types.Transaction{To: msg.To, Data: msg.Data}) {
			vmerr = nativeTransfer(st.evm, msg.From, *msg.To, value)
		} else {
			ret, st.gasRemaining, vmerr = st.evm.Call(msg.From, *msg.To, msg.Data, st.gasRemaining, value)
		}
	}

	peakGasUsed := st.gasUsed()
	refunded := st.refundGas()

	// Comisiones: propina al proponente y base fee a la tesorería/quema.
	usedGas := st.gasUsed()
	baseFee := st.evm.Context.BaseFee
	tip := types.Amount{}
	if msg.GasPrice.Gt(baseFee) {
		tip = msg.GasPrice.Sub(baseFee)
	}
	split := SplitFees(msg.GasPrice.Sub(tip), tip, usedGas)
	if !split.Tip.IsZero() {
		st.state.AddBalance(st.evm.Context.Coinbase, split.Tip)
	}
	if t := st.evm.ChainConfig.Fees.Treasury; t != (types.Address{}) && !split.Burned.IsZero() {
		st.state.AddBalance(t, split.Burned)
	}
	return &ExecutionResult{
		UsedGas: usedGas, MaxUsedGas: peakGasUsed, RefundedGas: refunded,
		Err: vmerr, ReturnData: ret, ContractAddress: contract,
	}, nil
}

// gasUsed es el gas consumido hasta ahora.
func (st *stateTransition) gasUsed() uint64 { return st.initialGas - st.gasRemaining }

// refundGas aplica el reembolso acotado y devuelve el gas sobrante.
func (st *stateTransition) refundGas() uint64 {
	refund := st.gasUsed() / MaxRefundDivisor // EIP-3529: como mucho 1/5
	if r := st.state.GetRefund(); r < refund {
		refund = r
	}
	st.gasRemaining += refund
	// Se devuelve al remitente el gas no usado al precio efectivo.
	remaining := st.msg.GasPrice.MulUint64(st.gasRemaining)
	st.state.AddBalance(st.msg.From, remaining)
	// Y el gas vuelve al bloque.
	st.gp.AddGas(st.gasRemaining)
	return refund
}
