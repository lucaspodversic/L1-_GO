package execution

// Este archivo implementa los precompilados de hash y copia:
//
//   - 0x02 SHA256:    60 + 12 gas por palabra.
//   - 0x03 RIPEMD160: 600 + 120 gas por palabra (salida rellenada a 32).
//   - 0x04 IDENTITY:  15 + 3 gas por palabra (copia la entrada).
//   - 0x09 BLAKE2F:   1 gas por ronda (función de compresión F, EIP-152).

import (
	"encoding/binary"
	"errors"
	"math/bits"

	"golang.org/x/crypto/ripemd160" //nolint:staticcheck // requerido por compatibilidad EVM

	"github.com/l1/l1/crypto"
)

// Costes de los precompilados de hash.
const (
	Sha256BaseGas     uint64 = 60
	Sha256PerWordGas  uint64 = 12
	Ripemd160BaseGas  uint64 = 600
	Ripemd160WordGas  uint64 = 120
	IdentityBaseGas   uint64 = 15
	IdentityPerWordGs uint64 = 3
	Blake2FInputLen          = 213
)

type sha256hash struct{}

func (c *sha256hash) RequiredGas(input []byte) uint64 {
	return uint64(len(input)+31)/32*Sha256PerWordGas + Sha256BaseGas
}

func (c *sha256hash) Run(input []byte) ([]byte, error) {
	h := crypto.Sha256(input)
	return h[:], nil
}

type ripemd160hash struct{}

func (c *ripemd160hash) RequiredGas(input []byte) uint64 {
	return uint64(len(input)+31)/32*Ripemd160WordGas + Ripemd160BaseGas
}

func (c *ripemd160hash) Run(input []byte) ([]byte, error) {
	h := ripemd160.New()
	h.Write(input)
	return leftPad32(h.Sum(nil)), nil
}

type dataCopy struct{}

func (c *dataCopy) RequiredGas(input []byte) uint64 {
	return uint64(len(input)+31)/32*IdentityPerWordGs + IdentityBaseGas
}

// Run devuelve una copia (el llamador puede modificar la entrada después).
func (c *dataCopy) Run(input []byte) ([]byte, error) {
	return append([]byte(nil), input...), nil
}

// ---------------------------------------------------------------------------
// BLAKE2F (EIP-152)
// ---------------------------------------------------------------------------

var (
	errBlake2FInputLength = errors.New("blake2f: longitud de entrada inválida")
	errBlake2FFinalFlag   = errors.New("blake2f: indicador final inválido")
)

type blake2F struct{}

// RequiredGas es el número de rondas (primeros 4 bytes, big-endian).
func (c *blake2F) RequiredGas(input []byte) uint64 {
	if len(input) != Blake2FInputLen {
		return 0 // Run fallará; no cobramos nada extra
	}
	return uint64(binary.BigEndian.Uint32(input[0:4]))
}

// Run decodifica rounds(4) || h(64) || m(128) || t(16) || f(1); h, m y t en
// little-endian como en la especificación de BLAKE2b.
func (c *blake2F) Run(input []byte) ([]byte, error) {
	if len(input) != Blake2FInputLen {
		return nil, errBlake2FInputLength
	}
	if input[212] > 1 {
		return nil, errBlake2FFinalFlag
	}
	rounds := binary.BigEndian.Uint32(input[0:4])
	final := input[212] == 1
	var h [8]uint64
	var m [16]uint64
	for i := 0; i < 8; i++ {
		h[i] = binary.LittleEndian.Uint64(input[4+i*8:])
	}
	for i := 0; i < 16; i++ {
		m[i] = binary.LittleEndian.Uint64(input[68+i*8:])
	}
	t := [2]uint64{binary.LittleEndian.Uint64(input[196:]), binary.LittleEndian.Uint64(input[204:])}
	blake2bF(&h, m, t, final, rounds)
	out := make([]byte, 64)
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint64(out[i*8:], h[i])
	}
	return out, nil
}

// blake2bIV es el vector inicial de BLAKE2b (igual que SHA-512).
var blake2bIV = [8]uint64{
	0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
	0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
}

// blake2bSigma son las permutaciones de mensaje por ronda.
var blake2bSigma = [10][16]byte{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
	{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
	{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
	{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
	{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
	{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
	{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
	{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
}

// blake2bF es la función de compresión F de BLAKE2b con número de rondas
// arbitrario (RFC 7693, sección 3.2).
func blake2bF(h *[8]uint64, m [16]uint64, t [2]uint64, final bool, rounds uint32) {
	var v [16]uint64
	copy(v[:8], h[:])
	copy(v[8:], blake2bIV[:])
	v[12] ^= t[0]
	v[13] ^= t[1]
	if final {
		v[14] = ^v[14]
	}
	g := func(a, b, c, d int, x, y uint64) {
		v[a] = v[a] + v[b] + x
		v[d] = bits.RotateLeft64(v[d]^v[a], -32)
		v[c] = v[c] + v[d]
		v[b] = bits.RotateLeft64(v[b]^v[c], -24)
		v[a] = v[a] + v[b] + y
		v[d] = bits.RotateLeft64(v[d]^v[a], -16)
		v[c] = v[c] + v[d]
		v[b] = bits.RotateLeft64(v[b]^v[c], -63)
	}
	for r := uint32(0); r < rounds; r++ {
		s := &blake2bSigma[r%10]
		g(0, 4, 8, 12, m[s[0]], m[s[1]])
		g(1, 5, 9, 13, m[s[2]], m[s[3]])
		g(2, 6, 10, 14, m[s[4]], m[s[5]])
		g(3, 7, 11, 15, m[s[6]], m[s[7]])
		g(0, 5, 10, 15, m[s[8]], m[s[9]])
		g(1, 6, 11, 12, m[s[10]], m[s[11]])
		g(2, 7, 8, 13, m[s[12]], m[s[13]])
		g(3, 4, 9, 14, m[s[14]], m[s[15]])
	}
	for i := 0; i < 8; i++ {
		h[i] ^= v[i] ^ v[i+8]
	}
}
