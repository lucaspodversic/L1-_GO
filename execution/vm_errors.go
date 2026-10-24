package execution

// Este archivo declara los errores de la capa de ejecución. Se dividen en:
//
//   - Errores de la VM: ocurren dentro de una llamada y hacen que esa
//     llamada falle (la transacción se incluye igualmente en el bloque con
//     estado "fallido" y paga el gas).
//   - Errores de consenso de transacción: hacen que la transacción sea
//     inválida y NO pueda incluirse en un bloque (nonce, fondos, gas...).
//
// También incluye la decodificación del motivo de un REVERT
// (Error(string) y Panic(uint256) de Solidity).

import (
	"errors"
	"fmt"
	"math/big"
)

// Errores de la VM.
var (
	ErrOutOfGas                 = errors.New("sin gas")
	ErrCodeStoreOutOfGas        = errors.New("sin gas para almacenar el código del contrato")
	ErrDepth                    = errors.New("profundidad máxima de llamadas superada")
	ErrInsufficientBalance      = errors.New("saldo insuficiente para la transferencia")
	ErrContractAddressCollision = errors.New("colisión de dirección de contrato")
	ErrExecutionReverted        = errors.New("ejecución revertida")
	ErrMaxCodeSizeExceeded      = errors.New("tamaño máximo de código superado")
	ErrMaxInitCodeSizeExceeded  = errors.New("tamaño máximo de initcode superado")
	ErrInvalidJump              = errors.New("destino de salto inválido")
	ErrWriteProtection          = errors.New("protección de escritura (contexto estático)")
	ErrReturnDataOutOfBounds    = errors.New("lectura fuera de los datos de retorno")
	ErrGasUintOverflow          = errors.New("desbordamiento del cálculo de gas")
	ErrInvalidCode              = errors.New("código inválido: comienza por 0xEF")
	ErrNonceUintOverflow        = errors.New("desbordamiento del nonce")
	ErrExecutionAborted         = errors.New("ejecución abortada")
)

// Errores que invalidan una transacción (no puede entrar en un bloque).
var (
	ErrNonceTooLow          = errors.New("nonce demasiado bajo")
	ErrNonceTooHigh         = errors.New("nonce demasiado alto")
	ErrNonceMax             = errors.New("nonce máximo alcanzado")
	ErrGasLimitReached      = errors.New("límite de gas del bloque alcanzado")
	ErrInsufficientFunds    = errors.New("fondos insuficientes para gas * precio + valor")
	ErrIntrinsicGas         = errors.New("gas inferior al gas intrínseco")
	ErrFeeCapTooLow         = errors.New("max fee per gas inferior a la base fee del bloque")
	ErrTipAboveFeeCap       = errors.New("max priority fee per gas superior a max fee per gas")
	ErrSenderNoEOA          = errors.New("el remitente no es una EOA (tiene código)")
	ErrGasLimitTooHigh      = errors.New("gas de la transacción superior al máximo")
	ErrInitCodeTooLarge     = errors.New("initcode de la transacción demasiado grande")
	ErrBlockGasUsedMismatch = errors.New("gas usado del bloque distinto del de la cabecera")
)

// ErrStackUnderflow indica que faltan operandos en la pila.
type ErrStackUnderflow struct {
	StackLen int
	Required int
}

func (e *ErrStackUnderflow) Error() string {
	return fmt.Sprintf("pila insuficiente (%d <=> %d)", e.StackLen, e.Required)
}

// ErrStackOverflow indica que se superaría el límite de 1024 elementos.
type ErrStackOverflow struct {
	StackLen int
	Limit    int
}

func (e *ErrStackOverflow) Error() string {
	return fmt.Sprintf("desbordamiento de pila (%d > %d)", e.StackLen, e.Limit)
}

// ErrInvalidOpCode indica un opcode no definido o INVALID (0xfe).
type ErrInvalidOpCode struct {
	Opcode OpCode
}

func (e *ErrInvalidOpCode) Error() string { return fmt.Sprintf("opcode inválido: %s", e.Opcode) }

// IsVMError informa si err es un fallo de ejecución (la transacción se
// incluye con estado fallido) y no un error de validez.
func IsVMError(err error) bool {
	if err == nil {
		return false
	}
	var u *ErrStackUnderflow
	var o *ErrStackOverflow
	var i *ErrInvalidOpCode
	if errors.As(err, &u) || errors.As(err, &o) || errors.As(err, &i) {
		return true
	}
	for _, e := range []error{ErrOutOfGas, ErrCodeStoreOutOfGas, ErrDepth, ErrInsufficientBalance,
		ErrContractAddressCollision, ErrExecutionReverted, ErrMaxCodeSizeExceeded,
		ErrMaxInitCodeSizeExceeded, ErrInvalidJump, ErrWriteProtection, ErrReturnDataOutOfBounds,
		ErrGasUintOverflow, ErrInvalidCode, ErrNonceUintOverflow} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

// Selectores de los errores estándar de Solidity.
var (
	revertSelector = []byte{0x08, 0xc3, 0x79, 0xa0} // Error(string)
	panicSelector  = []byte{0x4e, 0x48, 0x7b, 0x71} // Panic(uint256)
)

// panicReasons traduce los códigos de Panic(uint256) de Solidity.
var panicReasons = map[uint64]string{
	0x00: "pánico genérico",
	0x01: "assert fallido",
	0x11: "desbordamiento aritmético",
	0x12: "división o módulo por cero",
	0x21: "conversión a enum fuera de rango",
	0x22: "codificación de storage incorrecta",
	0x31: "pop sobre array vacío",
	0x32: "índice de array fuera de rango",
	0x41: "memoria excesiva",
	0x51: "llamada a función interna no inicializada",
}

// UnpackRevert decodifica los datos de un REVERT. Devuelve el mensaje y si
// se pudo interpretar.
func UnpackRevert(data []byte) (string, bool) {
	if len(data) < 4 {
		return "", false
	}
	switch {
	case string(data[:4]) == string(revertSelector):
		vals, err := DecodeABI([]string{"string"}, data[4:])
		if err != nil {
			return "", false
		}
		return vals[0].(string), true
	case string(data[:4]) == string(panicSelector):
		if len(data) < 36 {
			return "", false
		}
		code := new(big.Int).SetBytes(data[4:36])
		if code.IsUint64() {
			if r, ok := panicReasons[code.Uint64()]; ok {
				return fmt.Sprintf("panic: %s (0x%x)", r, code), true
			}
		}
		return fmt.Sprintf("panic: código desconocido 0x%x", code), true
	}
	return "", false
}

// RevertError envuelve ErrExecutionReverted con el motivo decodificado y
// los datos crudos (útil para eth_call / eth_estimateGas).
type RevertError struct {
	Reason string
	Data   []byte
}

// NewRevertError construye el error a partir de los datos devueltos.
func NewRevertError(data []byte) *RevertError {
	reason, ok := UnpackRevert(data)
	if !ok {
		reason = ""
	}
	return &RevertError{Reason: reason, Data: append([]byte(nil), data...)}
}

func (e *RevertError) Error() string {
	if e.Reason == "" {
		return ErrExecutionReverted.Error()
	}
	return ErrExecutionReverted.Error() + ": " + e.Reason
}

// Unwrap permite errors.Is(err, ErrExecutionReverted).
func (e *RevertError) Unwrap() error { return ErrExecutionReverted }
