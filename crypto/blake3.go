package crypto

// BLAKE3 es un hash moderno muy rápido (paralelizable, SIMD). Lo usamos donde
// no hace falta compatibilidad con Ethereum y sí velocidad: identificadores de
// mensajes gossip, deduplicación P2P, árboles de Merkle de fragmentos de
// estado para sync. Además ofrece modos con clave (MAC) y derivación de
// claves con contexto, que aprovechamos para separar dominios.

import (
	"hash"

	"lukechampine.com/blake3"
)

// Blake3 devuelve BLAKE3-256 de la concatenación de data.
func Blake3(data ...[]byte) [32]byte { return sumWith(blake3.New(32, nil), data...) }

// Blake3Keyed devuelve BLAKE3 en modo con clave (MAC de 32 bytes). La clave
// debe medir exactamente 32 bytes; si no, entra en pánico (error de programación).
func Blake3Keyed(key [32]byte, data ...[]byte) [32]byte {
	return sumWith(blake3.New(32, key[:]), data...)
}

// Blake3DeriveKey deriva una clave de len(out) bytes a partir de material
// secreto y un contexto fijo y único por uso (p. ej. "l1 p2p session v1").
// Distintos contextos producen claves independientes.
func Blake3DeriveKey(context string, material []byte, out []byte) {
	blake3.DeriveKey(out, context, material)
}

// Blake3XOF devuelve n bytes de salida extensible (XOF) de BLAKE3(data).
func Blake3XOF(n int, data ...[]byte) []byte {
	h := blake3.New(32, nil)
	for _, d := range data {
		h.Write(d)
	}
	out := make([]byte, n)
	// XOF() devuelve un lector de la salida de longitud arbitraria.
	_, _ = h.XOF().Read(out)
	return out
}

// Blake3Hasher implementa Hasher con BLAKE3-256.
type Blake3Hasher struct{}

// Algo implementa Hasher.
func (Blake3Hasher) Algo() HashAlgo { return AlgoBlake3 }

// Size implementa Hasher.
func (Blake3Hasher) Size() int { return 32 }

// Sum implementa Hasher.
func (Blake3Hasher) Sum(data ...[]byte) [32]byte { return Blake3(data...) }

// New implementa Hasher.
func (Blake3Hasher) New() hash.Hash { return blake3.New(32, nil) }
