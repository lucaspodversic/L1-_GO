package crypto

// SHA-256 se usa donde se necesita un hash estandarizado: precompilado
// SHA256 de la VM (dirección 0x02), PBKDF2/HMAC de BIP-39/BIP-32, checksums
// de mnemónicos y derivación de salidas VRF. Viene de la biblioteca estándar.

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

// Sha256 devuelve SHA-256 de la concatenación de data.
func Sha256(data ...[]byte) [32]byte { return sumWith(sha256.New(), data...) }

// DoubleSha256 devuelve SHA-256(SHA-256(data)), el esquema de Bitcoin;
// resistente a ataques de extensión de longitud.
func DoubleSha256(data ...[]byte) [32]byte {
	first := Sha256(data...)
	return sha256.Sum256(first[:])
}

// HmacSha256 devuelve HMAC-SHA256(key, data).
func HmacSha256(key []byte, data ...[]byte) [32]byte {
	m := hmac.New(sha256.New, key)
	for _, d := range data {
		m.Write(d)
	}
	var out [32]byte
	m.Sum(out[:0])
	return out
}

// HmacSha512 devuelve HMAC-SHA512(key, data) (64 bytes), base de BIP-32.
func HmacSha512(key []byte, data ...[]byte) []byte {
	m := hmac.New(sha512.New, key)
	for _, d := range data {
		m.Write(d)
	}
	return m.Sum(nil)
}

// SHA256Hasher implementa Hasher con SHA-256.
type SHA256Hasher struct{}

// Algo implementa Hasher.
func (SHA256Hasher) Algo() HashAlgo { return AlgoSHA256 }

// Size implementa Hasher.
func (SHA256Hasher) Size() int { return 32 }

// Sum implementa Hasher.
func (SHA256Hasher) Sum(data ...[]byte) [32]byte { return Sha256(data...) }

// New implementa Hasher.
func (SHA256Hasher) New() hash.Hash { return sha256.New() }
