// Package crypto reúne las primitivas criptográficas de la cadena:
//
//   - Funciones de hash: Keccak-256 (estado, direcciones, txs), SHA-256
//     (compatibilidad, PBKDF2/HMAC) y BLAKE3 (hash rápido para P2P/merkle).
//   - Firmas: secp256k1 recuperable (cuentas de usuario, compatible con
//     Ethereum), Ed25519 (identidad de nodos P2P) y BLS12-381 (votos de
//     consenso agregables en Quorum Certificates).
//   - Abstracciones de claves (keypair.go), firmantes (signer.go) y
//     verificadores (verifier.go), incluida la firma/recuperación de
//     transacciones.
//   - Árboles de Merkle binarios con pruebas de inclusión, VRF basada en BLS
//     para elección de líder, mnemónicos BIP-39 con derivación BIP-32/SLIP-10
//     y generadores aleatorios seguros y deterministas.
//
// Dependencias externas (todas en Go puro, sin cgo):
//
//   - golang.org/x/crypto (sha3, pbkdf2, hkdf, chacha20).
//   - github.com/decred/dcrd/dcrec/secp256k1/v4 (curva secp256k1, RFC 6979).
//   - github.com/consensys/gnark-crypto/ecc/bls12-381 (pairings BLS12-381).
//   - lukechampine.com/blake3.
//
// Este archivo define la interfaz común Hasher, que permite que estructuras
// como el árbol de Merkle sean genéricas respecto de la función de hash.
package crypto

import (
	"fmt"
	"hash"
)

// HashAlgo identifica una función de hash soportada.
type HashAlgo uint8

const (
	// AlgoKeccak256 es Keccak-256 (Ethereum).
	AlgoKeccak256 HashAlgo = iota + 1
	// AlgoSHA256 es SHA-256 (FIPS 180-4).
	AlgoSHA256
	// AlgoBlake3 es BLAKE3 con salida de 32 bytes.
	AlgoBlake3
)

// String devuelve el nombre del algoritmo.
func (a HashAlgo) String() string {
	switch a {
	case AlgoKeccak256:
		return "keccak256"
	case AlgoSHA256:
		return "sha256"
	case AlgoBlake3:
		return "blake3"
	default:
		return fmt.Sprintf("algo(%d)", uint8(a))
	}
}

// Hasher es la interfaz común de las funciones de hash de 32 bytes.
// Las implementaciones son seguras para uso concurrente (no guardan estado:
// cada llamada crea su propio contexto de hash).
type Hasher interface {
	// Algo identifica el algoritmo.
	Algo() HashAlgo
	// Size devuelve el tamaño de la salida en bytes (32 para todos).
	Size() int
	// Sum hashea la concatenación de los argumentos.
	Sum(data ...[]byte) [32]byte
	// New devuelve un hash.Hash incremental (para streaming de datos grandes).
	New() hash.Hash
}

// HasherFor devuelve el Hasher de un algoritmo, o error si no existe.
func HasherFor(a HashAlgo) (Hasher, error) {
	switch a {
	case AlgoKeccak256:
		return KeccakHasher{}, nil
	case AlgoSHA256:
		return SHA256Hasher{}, nil
	case AlgoBlake3:
		return Blake3Hasher{}, nil
	default:
		return nil, fmt.Errorf("crypto: algoritmo de hash desconocido %d", a)
	}
}

// sumWith es la implementación común de Sum para cualquier constructor de
// hash.Hash: escribe todos los fragmentos y vuelca el resultado en un [32]byte.
func sumWith(h hash.Hash, data ...[]byte) (out [32]byte) {
	for _, d := range data {
		h.Write(d) // hash.Hash.Write nunca falla.
	}
	h.Sum(out[:0])
	return out
}
