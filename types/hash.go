package types

// Este archivo define Hash, el identificador de 32 bytes usado para bloques,
// transacciones, raíces de tries y código de contratos, junto con las
// funciones Keccak-256 que lo producen.
//
// Keccak-256 vive aquí (y no sólo en el paquete crypto) porque types lo
// necesita para calcular hashes de cabeceras y transacciones, y crypto
// importa types: duplicar esta función mínima evita un ciclo de imports.

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/sha3"
)

// Hash es un hash Keccak-256 de 32 bytes. Es un arreglo (no un slice), así
// que es comparable con == y sirve como clave de mapas.
type Hash [HashLength]byte

// EmptyRootHash es la raíz de un trie vacío: Keccak256(RLP("")) =
// 0x56e81f17...b421. Se usa como StorageRoot de cuentas sin almacenamiento y
// como TxRoot de bloques sin transacciones.
var EmptyRootHash = Keccak256Hash(RLPEmptyString)

// EmptyCodeHash es Keccak256 del código vacío (0xc5d24601...a470): el
// CodeHash de toda cuenta que no es contrato.
var EmptyCodeHash = Keccak256Hash(nil)

// EmptyListHash es Keccak256(RLP([])); útil para listas vacías hasheadas.
var EmptyListHash = Keccak256Hash(RLPEmptyList)

// Keccak256 calcula el Keccak-256 "legacy" (el usado por Ethereum, previo a la
// estandarización FIPS-202 de SHA3) de la concatenación de los argumentos.
func Keccak256(data ...[]byte) []byte {
	h := sha3.NewLegacyKeccak256()
	for _, d := range data {
		h.Write(d) // Write de un hash nunca devuelve error.
	}
	return h.Sum(nil)
}

// Keccak256Hash es como Keccak256 pero devuelve un Hash.
func Keccak256Hash(data ...[]byte) (h Hash) {
	k := sha3.NewLegacyKeccak256()
	for _, d := range data {
		k.Write(d)
	}
	k.Sum(h[:0]) // Escribe directamente en el arreglo, sin alocar.
	return h
}

// BytesToHash convierte b en Hash. Si b es más largo se conservan los
// últimos 32 bytes; si es más corto se rellena con ceros a la izquierda
// (semántica de entero big-endian, igual que en la EVM).
func BytesToHash(b []byte) Hash {
	var h Hash
	h.SetBytes(b)
	return h
}

// HexToHash parsea un hash en hexadecimal ("0x" + 64 dígitos). A diferencia
// de BytesToHash, exige el largo exacto: un hash mal tipeado debe fallar.
func HexToHash(s string) (Hash, error) {
	b, err := DecodeHex(s)
	if err != nil {
		return Hash{}, err
	}
	if len(b) != HashLength {
		return Hash{}, fmt.Errorf("%w: hash de %d bytes", ErrInvalidLength, len(b))
	}
	return BytesToHash(b), nil
}

// MustHexToHash es como HexToHash pero entra en pánico ante error. Sólo para
// constantes conocidas en tiempo de compilación y tests.
func MustHexToHash(s string) Hash {
	h, err := HexToHash(s)
	if err != nil {
		panic(err)
	}
	return h
}

// SetBytes copia b en h con la misma semántica que BytesToHash.
func (h *Hash) SetBytes(b []byte) {
	if len(b) > len(h) {
		b = b[len(b)-HashLength:]
	}
	// Limpiamos primero para que el relleno a la izquierda sea cero.
	*h = Hash{}
	copy(h[HashLength-len(b):], b)
}

// Bytes devuelve una copia del hash como slice.
func (h Hash) Bytes() []byte { return append([]byte(nil), h[:]...) }

// Hex devuelve el hash en hexadecimal con prefijo "0x".
func (h Hash) Hex() string { return EncodeHex(h[:]) }

// String implementa fmt.Stringer.
func (h Hash) String() string { return h.Hex() }

// TerminalString devuelve una forma abreviada ("0xabcd…1234") para logs.
func (h Hash) TerminalString() string {
	return fmt.Sprintf("0x%s…%s", hex.EncodeToString(h[:2]), hex.EncodeToString(h[30:]))
}

// IsZero informa si el hash es todo ceros (valor "ausente").
func (h Hash) IsZero() bool { return h == Hash{} }

// Cmp compara lexicográficamente dos hashes (-1, 0, 1); útil para ordenar.
func (h Hash) Cmp(o Hash) int { return bytes.Compare(h[:], o[:]) }

// MarshalText implementa encoding.TextMarshaler (JSON como "0x...").
func (h Hash) MarshalText() ([]byte, error) { return []byte(h.Hex()), nil }

// UnmarshalText implementa encoding.TextUnmarshaler.
func (h *Hash) UnmarshalText(text []byte) error {
	v, err := HexToHash(string(text))
	if err != nil {
		return err
	}
	*h = v
	return nil
}

// EncodeRLP codifica el hash como string RLP de 32 bytes.
func (h Hash) EncodeRLP() []byte { return EncodeBytes(h[:]) }
