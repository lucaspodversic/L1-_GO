package crypto

// Keccak-256 es la función de hash principal del protocolo (heredada de
// Ethereum): hashes de bloques y transacciones, claves del trie de estado,
// direcciones y selectores de la VM. Se usa el Keccak "legacy" (padding
// original 0x01), que NO es igual a SHA3-256 de FIPS-202 (padding 0x06).

import (
	"hash"

	"github.com/l1/l1/types"
	"golang.org/x/crypto/sha3"
)

// Keccak256 devuelve el Keccak-256 de la concatenación de data.
func Keccak256(data ...[]byte) []byte { return types.Keccak256(data...) }

// Keccak256Hash devuelve el Keccak-256 como types.Hash.
func Keccak256Hash(data ...[]byte) types.Hash { return types.Keccak256Hash(data...) }

// Keccak512 devuelve el Keccak-512 legacy (64 bytes); lo usan algunos
// esquemas de derivación y es barato de exponer.
func Keccak512(data ...[]byte) []byte {
	h := sha3.NewLegacyKeccak512()
	for _, d := range data {
		h.Write(d)
	}
	return h.Sum(nil)
}

// NewKeccak256 devuelve un hash.Hash incremental de Keccak-256.
func NewKeccak256() hash.Hash { return sha3.NewLegacyKeccak256() }

// KeccakHasher implementa Hasher con Keccak-256.
type KeccakHasher struct{}

// Algo implementa Hasher.
func (KeccakHasher) Algo() HashAlgo { return AlgoKeccak256 }

// Size implementa Hasher.
func (KeccakHasher) Size() int { return 32 }

// Sum implementa Hasher.
func (KeccakHasher) Sum(data ...[]byte) [32]byte { return sumWith(sha3.NewLegacyKeccak256(), data...) }

// New implementa Hasher.
func (KeccakHasher) New() hash.Hash { return sha3.NewLegacyKeccak256() }
