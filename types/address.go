package types

// Este archivo define Address, el identificador de 20 bytes de una cuenta,
// con checksum EIP-55 y las funciones de derivación de direcciones de
// contratos (CREATE y CREATE2) que necesitará la VM.

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
)

// Address es una dirección de cuenta: los últimos 20 bytes del Keccak-256 de
// la clave pública secp256k1 sin comprimir (sin el byte 0x04 inicial).
type Address [AddressLength]byte

// ZeroAddress es la dirección nula; se usa como "sin destino" en algunos
// contextos (p. ej. coinbase indefinido). OJO: una transacción de creación de
// contrato se marca con To == nil, no con ZeroAddress.
var ZeroAddress = Address{}

// BytesToAddress convierte b en Address (conserva los últimos 20 bytes o
// rellena con ceros a la izquierda).
func BytesToAddress(b []byte) Address {
	var a Address
	a.SetBytes(b)
	return a
}

// HexToAddress parsea una dirección "0x" + 40 dígitos hexadecimales.
// Si la cadena mezcla mayúsculas y minúsculas, se exige que el checksum
// EIP-55 sea correcto (protección contra errores de tipeo); si está toda en
// minúsculas o toda en mayúsculas se acepta sin checksum.
func HexToAddress(s string) (Address, error) {
	b, err := DecodeHex(s)
	if err != nil {
		return Address{}, err
	}
	if len(b) != AddressLength {
		return Address{}, fmt.Errorf("%w: dirección de %d bytes", ErrInvalidLength, len(b))
	}
	a := BytesToAddress(b)
	body := s[2:]
	if body != strings.ToLower(body) && body != strings.ToUpper(body) {
		if a.Hex() != "0x"+body {
			return Address{}, ErrBadChecksum
		}
	}
	return a, nil
}

// MustHexToAddress es como HexToAddress pero entra en pánico; sólo para tests
// y constantes.
func MustHexToAddress(s string) Address {
	a, err := HexToAddress(s)
	if err != nil {
		panic(err)
	}
	return a
}

// IsHexAddress informa si s es sintácticamente una dirección válida.
func IsHexAddress(s string) bool {
	_, err := HexToAddress(s)
	return err == nil
}

// SetBytes copia b en a (semántica big-endian, como BytesToAddress).
func (a *Address) SetBytes(b []byte) {
	if len(b) > len(a) {
		b = b[len(b)-AddressLength:]
	}
	*a = Address{}
	copy(a[AddressLength-len(b):], b)
}

// Bytes devuelve una copia de la dirección como slice.
func (a Address) Bytes() []byte { return append([]byte(nil), a[:]...) }

// Hash devuelve la dirección rellenada a 32 bytes (útil en la EVM, donde las
// direcciones viajan como palabras de 256 bits).
func (a Address) Hash() Hash { return BytesToHash(a[:]) }

// Hex devuelve la dirección con checksum EIP-55: se hashea la forma en
// minúsculas y cada letra se pone en mayúscula si el nibble correspondiente
// del hash es >= 8.
func (a Address) Hex() string {
	lower := hex.EncodeToString(a[:])
	sum := Keccak256([]byte(lower))
	out := []byte(lower)
	for i := range out {
		c := out[i]
		if c < 'a' || c > 'f' {
			continue // los dígitos no tienen mayúscula
		}
		// Nibble i del hash: alto si i es par, bajo si es impar.
		nibble := sum[i/2]
		if i%2 == 0 {
			nibble >>= 4
		} else {
			nibble &= 0x0f
		}
		if nibble >= 8 {
			out[i] = c - 32 // a mayúscula
		}
	}
	return "0x" + string(out)
}

// String implementa fmt.Stringer.
func (a Address) String() string { return a.Hex() }

// IsZero informa si es la dirección nula.
func (a Address) IsZero() bool { return a == Address{} }

// Cmp compara lexicográficamente dos direcciones.
func (a Address) Cmp(o Address) int { return bytes.Compare(a[:], o[:]) }

// MarshalText implementa encoding.TextMarshaler (JSON con checksum).
func (a Address) MarshalText() ([]byte, error) { return []byte(a.Hex()), nil }

// UnmarshalText implementa encoding.TextUnmarshaler.
func (a *Address) UnmarshalText(text []byte) error {
	v, err := HexToAddress(string(text))
	if err != nil {
		return err
	}
	*a = v
	return nil
}

// EncodeRLP codifica la dirección como string RLP de 20 bytes.
func (a Address) EncodeRLP() []byte { return EncodeBytes(a[:]) }

// CreateAddress calcula la dirección de un contrato creado con CREATE (o con
// una transacción sin destinatario): Keccak256(RLP([sender, nonce]))[12:].
func CreateAddress(sender Address, nonce uint64) Address {
	enc := EncodeList(EncodeBytes(sender[:]), EncodeUint(nonce))
	return BytesToAddress(Keccak256(enc)[12:])
}

// CreateAddress2 calcula la dirección de un contrato creado con CREATE2
// (EIP-1014): Keccak256(0xff ++ sender ++ salt ++ Keccak256(initCode))[12:].
// Permite conocer la dirección antes de desplegar.
func CreateAddress2(sender Address, salt Hash, initCodeHash Hash) Address {
	return BytesToAddress(Keccak256([]byte{0xff}, sender[:], salt[:], initCodeHash[:])[12:])
}
