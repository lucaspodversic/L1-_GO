package execution

// Este archivo define la interfaz de los contratos precompilados, el
// registro de los activos y los precompilados aritméticos: MODEXP (0x05,
// con el gas de EIP-2565) y las operaciones sobre la curva alt_bn128/BN254
// (0x06 suma, 0x07 multiplicación escalar, 0x08 comprobación de
// emparejamiento; gas de EIP-1108), implementadas con gnark-crypto. Los
// precompilados de hash están en precompile_sha.go y ECRECOVER en
// precompile_ecrecover.go.
//
// Desviación documentada: no se incluye el precompilado 0x0a (evaluación
// de puntos KZG) porque la cadena no admite blobs.

import (
	"errors"
	"math"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	"github.com/l1/l1/types"
)

// PrecompiledContract es un contrato implementado de forma nativa.
type PrecompiledContract interface {
	// RequiredGas calcula el gas que costará procesar input.
	RequiredGas(input []byte) uint64
	// Run ejecuta el contrato. Un error consume todo el gas de la llamada.
	Run(input []byte) ([]byte, error)
}

// precompileAddr construye la dirección 0x00..0n.
func precompileAddr(n byte) types.Address {
	var a types.Address
	a[19] = n
	return a
}

// activePrecompiles es el conjunto de precompilados de la cadena.
var activePrecompiles = map[types.Address]PrecompiledContract{
	precompileAddr(1): &ecrecover{},
	precompileAddr(2): &sha256hash{},
	precompileAddr(3): &ripemd160hash{},
	precompileAddr(4): &dataCopy{},
	precompileAddr(5): &bigModExp{},
	precompileAddr(6): &bn256Add{},
	precompileAddr(7): &bn256ScalarMul{},
	precompileAddr(8): &bn256Pairing{},
	precompileAddr(9): &blake2F{},
}

// precompileAddresses lista las direcciones en orden (para Prepare).
var precompileAddresses = func() []types.Address {
	out := make([]types.Address, 0, len(activePrecompiles))
	for i := byte(1); i <= 9; i++ {
		out = append(out, precompileAddr(i))
	}
	return out
}()

// PrecompileAddresses devuelve una copia de las direcciones activas.
func PrecompileAddresses() []types.Address {
	return append([]types.Address(nil), precompileAddresses...)
}

// IsPrecompile informa si addr es un precompilado.
func IsPrecompile(addr types.Address) bool { _, ok := activePrecompiles[addr]; return ok }

// RunPrecompiledContract cobra el gas y ejecuta el precompilado.
func RunPrecompiledContract(p PrecompiledContract, input []byte, suppliedGas uint64) (ret []byte, remainingGas uint64, err error) {
	gasCost := p.RequiredGas(input)
	if suppliedGas < gasCost {
		return nil, 0, ErrOutOfGas
	}
	suppliedGas -= gasCost
	output, err := p.Run(input)
	return output, suppliedGas, err
}

// getData devuelve data[start:start+size] rellenando con ceros por la
// derecha lo que quede fuera (semántica de lectura de los precompilados).
func getData(data []byte, start, size uint64) []byte {
	length := uint64(len(data))
	if start > length {
		start = length
	}
	end := start + size
	if end > length || end < start {
		end = length
	}
	out := make([]byte, size)
	copy(out, data[start:end])
	return out
}

// leftPad32 rellena con ceros por la izquierda hasta 32 bytes.
func leftPad32(b []byte) []byte {
	if len(b) >= 32 {
		return b
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// ---------------------------------------------------------------------------
// MODEXP (0x05) — EIP-198 con precios de EIP-2565
// ---------------------------------------------------------------------------

type bigModExp struct{}

// modexpLengths lee las tres longitudes (base, exponente, módulo).
func modexpLengths(input []byte) (baseLen, expLen, modLen *big.Int) {
	baseLen = new(big.Int).SetBytes(getData(input, 0, 32))
	expLen = new(big.Int).SetBytes(getData(input, 32, 32))
	modLen = new(big.Int).SetBytes(getData(input, 64, 32))
	return
}

// RequiredGas implementa la fórmula de EIP-2565:
// max(200, mult_complexity · iteraciones / 3).
func (c *bigModExp) RequiredGas(input []byte) uint64 {
	baseLen, expLen, modLen := modexpLengths(input)
	var body []byte
	if len(input) > 96 {
		body = input[96:]
	}
	// Cabeza del exponente: sus primeros min(expLen, 32) bytes.
	var expHead *big.Int
	if baseLen.BitLen() > 64 {
		expHead = new(big.Int) // la entrada no puede ser tan larga
	} else {
		headLen := uint64(32)
		if expLen.Cmp(big.NewInt(32)) < 0 {
			headLen = expLen.Uint64()
		}
		expHead = new(big.Int).SetBytes(getData(body, baseLen.Uint64(), headLen))
	}
	// Longitud ajustada del exponente.
	adjExpLen := new(big.Int)
	if expLen.Cmp(big.NewInt(32)) > 0 {
		adjExpLen.Sub(expLen, big.NewInt(32))
		adjExpLen.Mul(adjExpLen, big.NewInt(8))
	}
	if bl := expHead.BitLen(); bl > 0 {
		adjExpLen.Add(adjExpLen, big.NewInt(int64(bl-1)))
	}
	// Complejidad: ceil(max(baseLen, modLen)/8)^2.
	maxLen := baseLen
	if modLen.Cmp(maxLen) > 0 {
		maxLen = modLen
	}
	words := new(big.Int).Add(maxLen, big.NewInt(7))
	words.Rsh(words, 3)
	gas := new(big.Int).Mul(words, words)
	if adjExpLen.Sign() == 0 {
		adjExpLen.SetInt64(1)
	}
	gas.Mul(gas, adjExpLen)
	gas.Div(gas, big.NewInt(3))
	if gas.BitLen() > 64 {
		return math.MaxUint64
	}
	return max(gas.Uint64(), 200)
}

// Run calcula base^exp mod m. Con m = 0 el resultado son ceros.
func (c *bigModExp) Run(input []byte) ([]byte, error) {
	bl, el, ml := modexpLengths(input)
	if !bl.IsUint64() || !el.IsUint64() || !ml.IsUint64() {
		return nil, errors.New("modexp: longitudes fuera de rango")
	}
	baseLen, expLen, modLen := bl.Uint64(), el.Uint64(), ml.Uint64()
	if baseLen == 0 && modLen == 0 {
		return []byte{}, nil
	}
	var body []byte
	if len(input) > 96 {
		body = input[96:]
	}
	base := new(big.Int).SetBytes(getData(body, 0, baseLen))
	exp := new(big.Int).SetBytes(getData(body, baseLen, expLen))
	mod := new(big.Int).SetBytes(getData(body, baseLen+expLen, modLen))
	out := make([]byte, modLen)
	if mod.BitLen() == 0 {
		return out, nil // módulo cero: resultado cero por convención
	}
	var v *big.Int
	if base.BitLen() == 1 { // base 1: evita el cálculo
		v = new(big.Int).Mod(base, mod)
	} else {
		v = new(big.Int).Exp(base, exp, mod)
	}
	return v.FillBytes(out), nil
}

// ---------------------------------------------------------------------------
// BN254 (alt_bn128) — 0x06, 0x07, 0x08 (EIP-196/197, precios EIP-1108)
// ---------------------------------------------------------------------------

// Errores de decodificación de puntos.
var (
	errBN254InvalidField = errors.New("bn254: coordenada fuera del cuerpo")
	errBN254NotOnCurve   = errors.New("bn254: punto fuera de la curva")
	errBN254Subgroup     = errors.New("bn254: punto G2 fuera del subgrupo")
	errBN254PairingInput = errors.New("bn254: longitud de entrada de emparejamiento inválida")
)

// readFp lee un elemento del cuerpo base (32 bytes big-endian, < p).
func readFp(b []byte) (fp.Element, error) {
	var e fp.Element
	if err := e.SetBytesCanonical(b); err != nil {
		return e, errBN254InvalidField
	}
	return e, nil
}

// readG1 decodifica un punto de G1 (x || y); (0,0) es el infinito.
func readG1(b []byte) (*bn254.G1Affine, error) {
	x, err := readFp(b[0:32])
	if err != nil {
		return nil, err
	}
	y, err := readFp(b[32:64])
	if err != nil {
		return nil, err
	}
	p := &bn254.G1Affine{X: x, Y: y}
	if !p.IsOnCurve() { // gnark considera (0,0) en la curva (infinito)
		return nil, errBN254NotOnCurve
	}
	return p, nil
}

// readG2 decodifica un punto de G2. Ethereum codifica cada coordenada de
// Fp2 como (parte imaginaria || parte real).
func readG2(b []byte) (*bn254.G2Affine, error) {
	var vals [4]fp.Element
	for i := 0; i < 4; i++ {
		v, err := readFp(b[i*32 : (i+1)*32])
		if err != nil {
			return nil, err
		}
		vals[i] = v
	}
	p := &bn254.G2Affine{}
	p.X.A1, p.X.A0 = vals[0], vals[1]
	p.Y.A1, p.Y.A0 = vals[2], vals[3]
	if p.IsInfinity() {
		return p, nil
	}
	if !p.IsOnCurve() {
		return nil, errBN254NotOnCurve
	}
	if !p.IsInSubGroup() {
		return nil, errBN254Subgroup
	}
	return p, nil
}

// marshalG1 codifica un punto como x || y (64 bytes; infinito = ceros).
func marshalG1(p *bn254.G1Affine) []byte {
	out := make([]byte, 64)
	if p.IsInfinity() {
		return out
	}
	x, y := p.X.Bytes(), p.Y.Bytes()
	copy(out[0:32], x[:])
	copy(out[32:64], y[:])
	return out
}

type bn256Add struct{}

func (c *bn256Add) RequiredGas([]byte) uint64 { return 150 }

func (c *bn256Add) Run(input []byte) ([]byte, error) {
	a, err := readG1(getData(input, 0, 64))
	if err != nil {
		return nil, err
	}
	b, err := readG1(getData(input, 64, 64))
	if err != nil {
		return nil, err
	}
	// Sumamos en coordenadas jacobianas, que tratan bien el infinito y la
	// duplicación (a == b).
	var ja, jb bn254.G1Jac
	ja.FromAffine(a)
	jb.FromAffine(b)
	ja.AddAssign(&jb)
	var res bn254.G1Affine
	res.FromJacobian(&ja)
	return marshalG1(&res), nil
}

type bn256ScalarMul struct{}

func (c *bn256ScalarMul) RequiredGas([]byte) uint64 { return 6000 }

func (c *bn256ScalarMul) Run(input []byte) ([]byte, error) {
	p, err := readG1(getData(input, 0, 64))
	if err != nil {
		return nil, err
	}
	k := new(big.Int).SetBytes(getData(input, 64, 32))
	k.Mod(k, fr.Modulus()) // G1 tiene orden r: k y k mod r dan el mismo punto
	var res bn254.G1Affine
	if p.IsInfinity() || k.Sign() == 0 {
		res.SetInfinity()
	} else {
		res.ScalarMultiplication(p, k)
	}
	return marshalG1(&res), nil
}

type bn256Pairing struct{}

// RequiredGas: 45000 por par + 34000.
func (c *bn256Pairing) RequiredGas(input []byte) uint64 {
	return uint64(len(input)/192)*34000 + 45000
}

// Run devuelve 1 si el producto de los emparejamientos es la identidad.
func (c *bn256Pairing) Run(input []byte) ([]byte, error) {
	if len(input)%192 != 0 {
		return nil, errBN254PairingInput
	}
	var ps []bn254.G1Affine
	var qs []bn254.G2Affine
	for i := 0; i < len(input); i += 192 {
		p, err := readG1(input[i : i+64])
		if err != nil {
			return nil, err
		}
		q, err := readG2(input[i+64 : i+192])
		if err != nil {
			return nil, err
		}
		// Un par con algún infinito contribuye con 1: se omite.
		if p.IsInfinity() || q.IsInfinity() {
			continue
		}
		ps = append(ps, *p)
		qs = append(qs, *q)
	}
	out := make([]byte, 32)
	if len(ps) == 0 {
		out[31] = 1
		return out, nil
	}
	ok, err := bn254.PairingCheck(ps, qs)
	if err != nil {
		return nil, err
	}
	if ok {
		out[31] = 1
	}
	return out, nil
}
