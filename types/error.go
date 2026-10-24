package types

// Este archivo centraliza los errores del paquete types. Usamos errores
// "centinela" (variables comparables con errors.Is) para los casos comunes y
// un tipo estructurado (ValidationError) cuando conviene indicar qué campo
// falló, lo que facilita devolver mensajes útiles por RPC más adelante.

import (
	"errors"
	"fmt"
)

// Errores centinela de codificación y parseo.
var (
	// ErrInvalidLength indica que un slice de bytes no tiene el largo esperado
	// (por ejemplo, un hash que no mide 32 bytes).
	ErrInvalidLength = errors.New("types: largo inválido")
	// ErrInvalidHex indica una cadena hexadecimal mal formada.
	ErrInvalidHex = errors.New("types: hexadecimal inválido")
	// ErrMissingHexPrefix indica que falta el prefijo "0x" obligatorio.
	ErrMissingHexPrefix = errors.New("types: falta el prefijo 0x")
	// ErrBadChecksum indica una dirección con mayúsculas/minúsculas mixtas que
	// no respeta el checksum EIP-55.
	ErrBadChecksum = errors.New("types: checksum EIP-55 inválido")
)

// Errores centinela de RLP (ver codec.go).
var (
	// ErrRLPTruncated: el buffer terminó antes de lo que indicaba un prefijo.
	ErrRLPTruncated = errors.New("rlp: datos truncados")
	// ErrRLPNonCanonical: la codificación es válida pero no es la mínima, lo
	// que rompería la unicidad de los hashes.
	ErrRLPNonCanonical = errors.New("rlp: codificación no canónica")
	// ErrRLPTrailing: sobran bytes después del elemento decodificado.
	ErrRLPTrailing = errors.New("rlp: bytes sobrantes al final")
	// ErrRLPExpectedList: se esperaba una lista y vino un string.
	ErrRLPExpectedList = errors.New("rlp: se esperaba una lista")
	// ErrRLPExpectedString: se esperaba un string y vino una lista.
	ErrRLPExpectedString = errors.New("rlp: se esperaba un string")
	// ErrRLPUintOverflow: el entero no entra en el tipo destino.
	ErrRLPUintOverflow = errors.New("rlp: entero desbordado")
	// ErrRLPTooDeep: anidamiento excesivo (protección contra entradas hostiles).
	ErrRLPTooDeep = errors.New("rlp: anidamiento demasiado profundo")
	// ErrRLPListCount: la lista no tiene la cantidad de elementos esperada.
	ErrRLPListCount = errors.New("rlp: cantidad de elementos inesperada")
)

// Errores centinela de dominio (montos, firmas, transacciones, génesis).
var (
	// ErrAmountOverflow: el resultado supera 2^256-1.
	ErrAmountOverflow = errors.New("types: monto desbordado (> 2^256-1)")
	// ErrAmountUnderflow: el resultado sería negativo.
	ErrAmountUnderflow = errors.New("types: monto negativo")
	// ErrInvalidAmount: no se pudo parsear el monto.
	ErrInvalidAmount = errors.New("types: monto inválido")
	// ErrInvalidSignature: firma con valores fuera de rango.
	ErrInvalidSignature = errors.New("types: firma inválida")
	// ErrInvalidChainID: identificador de cadena nulo o inconsistente.
	ErrInvalidChainID = errors.New("types: chain id inválido")
	// ErrTxTypeNotSupported: tipo de transacción desconocido.
	ErrTxTypeNotSupported = errors.New("types: tipo de transacción no soportado")
	// ErrUnsignedTx: la transacción no tiene firma.
	ErrUnsignedTx = errors.New("types: transacción sin firmar")
	// ErrInvalidGenesis: el génesis no pasa la validación.
	ErrInvalidGenesis = errors.New("types: génesis inválido")
)

// ValidationError describe una validación fallida sobre un campo concreto.
// Implementa Unwrap para que errors.Is(err, Base) funcione.
type ValidationError struct {
	// Object es el tipo de objeto validado ("header", "tx", "genesis"...).
	Object string
	// Field es el campo que no pasó la validación.
	Field string
	// Reason es una explicación legible del problema.
	Reason string
	// Base es el error centinela asociado (puede ser nil).
	Base error
}

// Error implementa la interfaz error con un mensaje en formato
// "objeto.campo: motivo".
func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s.%s: %s", e.Object, e.Field, e.Reason)
}

// Unwrap devuelve el error base para encadenar con errors.Is / errors.As.
func (e *ValidationError) Unwrap() error { return e.Base }

// newValidationError es un atajo interno para construir ValidationError con
// formato printf en el motivo.
func newValidationError(base error, object, field, format string, args ...any) error {
	return &ValidationError{Object: object, Field: field, Reason: fmt.Sprintf(format, args...), Base: base}
}
