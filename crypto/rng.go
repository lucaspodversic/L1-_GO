package crypto

// Generadores de números aleatorios.
//
//   - Funciones "Secure*": aleatoriedad del sistema operativo (crypto/rand),
//     para claves, nonces y sales.
//   - DeterministicRNG: flujo pseudoaleatorio REPRODUCIBLE a partir de una
//     semilla (ChaCha20 IETF con nonce cero). Todos los nodos que parten de la
//     misma semilla (p. ej. el campo Random del bloque) obtienen exactamente la
//     misma secuencia, lo que permite barajar validadores o elegir comités de
//     forma consensuada. Se usa ChaCha20 de x/crypto en lugar de math/rand
//     porque su salida está fijada por un estándar (RFC 8439) y no puede
//     cambiar entre versiones de Go.

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"math/bits"

	"golang.org/x/crypto/chacha20"
)

// readerOrDefault devuelve r, o crypto/rand.Reader si r es nil.
func readerOrDefault(r io.Reader) io.Reader {
	if r == nil {
		return rand.Reader
	}
	return r
}

// SecureBytes devuelve n bytes aleatorios del sistema. crypto/rand no falla
// en sistemas soportados; si lo hiciera, el programa no puede continuar de
// forma segura y se entra en pánico.
func SecureBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic("crypto: fuente de aleatoriedad del sistema no disponible: " + err.Error())
	}
	return b
}

// SecureUint64 devuelve un uint64 aleatorio uniforme.
func SecureUint64() uint64 { return binary.LittleEndian.Uint64(SecureBytes(8)) }

// SecureHash32 devuelve 32 bytes aleatorios (útil para sales e IDs).
func SecureHash32() (out [32]byte) {
	copy(out[:], SecureBytes(32))
	return out
}

// DeterministicRNG es un generador reproducible basado en ChaCha20.
// No es seguro para uso concurrente.
type DeterministicRNG struct {
	c *chacha20.Cipher
}

// NewDeterministicRNG crea un generador a partir de una semilla de 32 bytes.
func NewDeterministicRNG(seed [32]byte) *DeterministicRNG {
	var nonce [chacha20.NonceSize]byte
	c, err := chacha20.NewUnauthenticatedCipher(seed[:], nonce[:])
	if err != nil {
		panic(err) // imposible: clave y nonce tienen tamaño fijo correcto
	}
	return &DeterministicRNG{c: c}
}

// NewDeterministicRNGFrom deriva la semilla de material arbitrario y de un
// contexto (BLAKE3 DeriveKey), p. ej. ("l1/leader-shuffle/v1", random||epoch).
func NewDeterministicRNGFrom(context string, material []byte) *DeterministicRNG {
	var seed [32]byte
	Blake3DeriveKey(context, material, seed[:])
	return NewDeterministicRNG(seed)
}

// Read implementa io.Reader llenando p con el flujo de clave. Nunca falla.
func (r *DeterministicRNG) Read(p []byte) (int, error) {
	clear(p)
	r.c.XORKeyStream(p, p) // keystream XOR ceros = keystream
	return len(p), nil
}

// Uint64 devuelve el siguiente uint64 del flujo.
func (r *DeterministicRNG) Uint64() uint64 {
	var b [8]byte
	r.Read(b[:])
	return binary.LittleEndian.Uint64(b[:])
}

// Uint64n devuelve un entero uniforme en [0, n) sin sesgo (método de Lemire
// con rechazo). n debe ser > 0.
func (r *DeterministicRNG) Uint64n(n uint64) uint64 {
	if n == 0 {
		panic("crypto: Uint64n(0)")
	}
	hi, lo := bits.Mul64(r.Uint64(), n)
	if lo < n {
		thresh := -n % n
		for lo < thresh {
			hi, lo = bits.Mul64(r.Uint64(), n)
		}
	}
	return hi
}

// Intn devuelve un int uniforme en [0, n).
func (r *DeterministicRNG) Intn(n int) int { return int(r.Uint64n(uint64(n))) }

// Shuffle permuta n elementos con Fisher-Yates usando swap(i, j).
func (r *DeterministicRNG) Shuffle(n int, swap func(i, j int)) {
	for i := n - 1; i > 0; i-- {
		swap(i, r.Intn(i+1))
	}
}

// Perm devuelve una permutación pseudoaleatoria de [0, n).
func (r *DeterministicRNG) Perm(n int) []int {
	p := make([]int, n)
	for i := range p {
		p[i] = i
	}
	r.Shuffle(n, func(i, j int) { p[i], p[j] = p[j], p[i] })
	return p
}

// WeightedIndex elige un índice con probabilidad proporcional a weights[i].
// Devuelve -1 si la suma de pesos es 0.
func (r *DeterministicRNG) WeightedIndex(weights []uint64) int {
	var total uint64
	for _, w := range weights {
		total += w
	}
	if total == 0 {
		return -1
	}
	x := r.Uint64n(total)
	for i, w := range weights {
		if x < w {
			return i
		}
		x -= w
	}
	return len(weights) - 1 // inalcanzable
}
