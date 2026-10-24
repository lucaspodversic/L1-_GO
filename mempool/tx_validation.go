// Package mempool implementa el pool de transacciones pendientes: valida
// las transacciones entrantes, las organiza por cuenta y nonce (listas
// "pending" ejecutables y "queue" futuras), aplica las reglas de reemplazo
// por subida de precio, desaloja las más baratas cuando se llena y entrega
// al proponente un iterador ordenado por propina efectiva (EIP-1559).
package mempool

// Este archivo contiene la validación de transacciones en dos fases:
//
//   - Sin estado (ValidateTxBasics): formato, tamaño, cadena, firma, gas
//     intrínseco, límites de gas del bloque y propina mínima. Es barata y
//     se hace antes de tomar el cerrojo del pool.
//   - Con estado (ValidateTxState): nonce no usado y saldo suficiente para
//     el coste máximo (gas·feeCap + valor), contando las transacciones del
//     mismo remitente ya presentes en el pool.

import (
	"errors"
	"fmt"

	"github.com/l1/l1/crypto"
	"github.com/l1/l1/execution"
	"github.com/l1/l1/types"
)

// Errores de admisión del pool.
var (
	ErrAlreadyKnown       = errors.New("transacción ya conocida")
	ErrInvalidSender      = errors.New("remitente inválido")
	ErrUnderpriced        = errors.New("transacción con precio insuficiente")
	ErrReplaceUnderpriced = errors.New("reemplazo con precio insuficiente")
	ErrTxPoolOverflow     = errors.New("pool lleno")
	ErrAccountLimit       = errors.New("límite de transacciones por cuenta alcanzado")
	ErrOversizedData      = errors.New("transacción demasiado grande")
	ErrGasLimit           = errors.New("gas superior al límite del bloque")
	ErrTipBelowMinimum    = errors.New("propina inferior al mínimo del nodo")
	ErrNonceGap           = errors.New("nonce demasiado adelantado")
	ErrFiltered           = errors.New("transacción rechazada por filtro")
	// Se reutilizan los errores de ejecución para nonce/saldo/gas.
	ErrNonceTooLow       = execution.ErrNonceTooLow
	ErrInsufficientFunds = execution.ErrInsufficientFunds
	ErrIntrinsicGas      = execution.ErrIntrinsicGas
)

// ValidationOptions son los parámetros de la validación sin estado.
type ValidationOptions struct {
	ChainID  types.ChainID
	MaxSize  uint64       // tamaño máximo codificado
	MaxGas   uint64       // límite de gas del bloque actual
	MinTip   types.Amount // propina mínima aceptada (salvo locales)
	Filters  TxFilter     // filtros adicionales (puede ser nil)
	Signer   crypto.TxSigner
	Local    bool // las locales no exigen MinTip
	MaxNonce uint64
}

// ValidateTxBasics hace las comprobaciones que no dependen del estado y
// devuelve el remitente recuperado.
func ValidateTxBasics(tx *types.Transaction, opts *ValidationOptions) (types.Address, error) {
	if opts.MaxSize > 0 && tx.Size() > opts.MaxSize {
		return types.Address{}, fmt.Errorf("%w: %d > %d", ErrOversizedData, tx.Size(), opts.MaxSize)
	}
	// Formato, firma canónica, cadena, tipo y límites de campos.
	if err := tx.ValidateBasic(opts.ChainID); err != nil {
		return types.Address{}, err
	}
	if opts.MaxGas > 0 && tx.Gas > opts.MaxGas {
		return types.Address{}, fmt.Errorf("%w: %d > %d", ErrGasLimit, tx.Gas, opts.MaxGas)
	}
	if tx.GasFeeCap.Lt(tx.GasTipCap) {
		return types.Address{}, execution.ErrTipAboveFeeCap
	}
	if tx.To == nil && uint64(len(tx.Data)) > types.MaxInitCodeSize {
		return types.Address{}, execution.ErrInitCodeTooLarge
	}
	from, err := opts.Signer.Sender(tx)
	if err != nil {
		return types.Address{}, fmt.Errorf("%w: %v", ErrInvalidSender, err)
	}
	gas, err := execution.TxIntrinsicGas(tx)
	if err != nil {
		return types.Address{}, err
	}
	if tx.Gas < gas {
		return types.Address{}, fmt.Errorf("%w: tiene %d, necesita %d", ErrIntrinsicGas, tx.Gas, gas)
	}
	if !opts.Local && tx.GasTipCap.Lt(opts.MinTip) {
		return types.Address{}, fmt.Errorf("%w: %s < %s", ErrTipBelowMinimum, tx.GasTipCap, opts.MinTip)
	}
	if opts.Filters != nil {
		if err := opts.Filters.Filter(tx, from); err != nil {
			return types.Address{}, fmt.Errorf("%w: %v", ErrFiltered, err)
		}
	}
	return from, nil
}

// StateReader es la vista mínima del estado que necesita el pool.
type StateReader interface {
	GetNonce(addr types.Address) uint64
	GetBalance(addr types.Address) types.Amount
}

// StateOptions son los datos necesarios para la validación con estado.
type StateOptions struct {
	State StateReader
	// ExistingCost es el coste de las txs del remitente ya en el pool con
	// nonce menor (deben poder pagarse todas). Si la tx reemplaza otra, se
	// descuenta el coste de la reemplazada.
	ExistingCost types.Amount
	// MaxNonceGap limita cuánto puede adelantarse el nonce.
	MaxNonceGap uint64
	// PendingNonce es el siguiente nonce esperado contando el pool.
	PendingNonce uint64
}

// ValidateTxState comprueba nonce y saldo frente al estado.
func ValidateTxState(tx *types.Transaction, from types.Address, opts *StateOptions) error {
	next := opts.State.GetNonce(from)
	if tx.Nonce < next {
		return fmt.Errorf("%w: siguiente %d, tx %d", ErrNonceTooLow, next, tx.Nonce)
	}
	if opts.MaxNonceGap > 0 && tx.Nonce > opts.PendingNonce+opts.MaxNonceGap {
		return fmt.Errorf("%w: pendiente %d, tx %d", ErrNonceGap, opts.PendingNonce, tx.Nonce)
	}
	bal := opts.State.GetBalance(from)
	need := tx.Cost().Add(opts.ExistingCost)
	if bal.Lt(need) {
		return fmt.Errorf("%w: saldo %s, necesita %s", ErrInsufficientFunds, bal, need)
	}
	return nil
}
