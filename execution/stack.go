package execution

// Este archivo define Word, el entero sin signo de 256 bits con el que opera
// la EVM, y Stack, la pila de hasta 1024 palabras.
//
// Word se representa como cuatro limbs de 64 bits en orden little-endian
// (w[0] es el limb menos significativo). Las operaciones frecuentes (suma,
// resta, multiplicación, comparaciones, bits y desplazamientos) se hacen con
// math/bits sin reservar memoria; las menos frecuentes y más complejas
// (división, módulo, ADDMOD/MULMOD) recurren a math/big, priorizando la
// corrección sobre la velocidad. Toda la aritmética es módulo 2^256, igual
// que en la EVM.

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"math/bits"
	"sync"

	"github.com/l1/l1/types"
)

// StackLimit es la profundidad máxima de la pila de la EVM.
const StackLimit = 1024

// Word es un entero sin signo de 256 bits (módulo 2^256).
type Word [4]uint64

// two256 es 2^256, usado para convertir desde/hacia big.Int con signo.
var two256 = new(big.Int).Lsh(big.NewInt(1), 256)

// NewWord crea una palabra a partir de un uint64.
func NewWord(v uint64) *Word { return &Word{v} }

// WordFromBig convierte un big.Int (se toma módulo 2^256; los negativos se
// interpretan en complemento a dos).
func WordFromBig(b *big.Int) *Word {
	var w Word
	w.SetFromBig(b)
	return &w
}

// WordFromAmount convierte un Amount (que ya está acotado a 256 bits).
func WordFromAmount(a types.Amount) *Word {
	var w Word
	b := a.Bytes32()
	w.SetBytes(b[:])
	return &w
}

// Clone devuelve una copia independiente.
func (z *Word) Clone() *Word { c := *z; return &c }

// Set copia x en z.
func (z *Word) Set(x *Word) *Word { *z = *x; return z }

// Clear pone z a cero.
func (z *Word) Clear() *Word { *z = Word{}; return z }

// SetOne pone z a uno.
func (z *Word) SetOne() *Word { *z = Word{1}; return z }

// SetUint64 asigna un uint64.
func (z *Word) SetUint64(v uint64) *Word { *z = Word{v}; return z }

// SetBytes interpreta b como big-endian; si b tiene más de 32 bytes se usan
// los 32 menos significativos (últimos).
func (z *Word) SetBytes(b []byte) *Word {
	if len(b) > 32 {
		b = b[len(b)-32:]
	}
	var buf [32]byte
	copy(buf[32-len(b):], b)
	z[3] = binary.BigEndian.Uint64(buf[0:8])
	z[2] = binary.BigEndian.Uint64(buf[8:16])
	z[1] = binary.BigEndian.Uint64(buf[16:24])
	z[0] = binary.BigEndian.Uint64(buf[24:32])
	return z
}

// SetFromBig asigna b módulo 2^256 (negativos en complemento a dos).
func (z *Word) SetFromBig(b *big.Int) *Word {
	v := new(big.Int).Mod(b, two256) // Mod de Go siempre devuelve >= 0
	var buf [32]byte
	v.FillBytes(buf[:])
	return z.SetBytes(buf[:])
}

// Bytes32 devuelve la representación big-endian de 32 bytes.
func (z *Word) Bytes32() (out [32]byte) {
	binary.BigEndian.PutUint64(out[0:8], z[3])
	binary.BigEndian.PutUint64(out[8:16], z[2])
	binary.BigEndian.PutUint64(out[16:24], z[1])
	binary.BigEndian.PutUint64(out[24:32], z[0])
	return out
}

// Bytes devuelve la representación big-endian mínima (sin ceros a la
// izquierda; vacía para el cero).
func (z *Word) Bytes() []byte {
	b := z.Bytes32()
	i := 0
	for i < 32 && b[i] == 0 {
		i++
	}
	return append([]byte(nil), b[i:]...)
}

// Hash interpreta la palabra como hash de 32 bytes.
func (z *Word) Hash() types.Hash { return types.Hash(z.Bytes32()) }

// SetHash asigna desde un hash de 32 bytes.
func (z *Word) SetHash(h types.Hash) *Word { return z.SetBytes(h[:]) }

// Address devuelve los 20 bytes menos significativos como dirección.
func (z *Word) Address() types.Address {
	b := z.Bytes32()
	return types.BytesToAddress(b[12:])
}

// SetAddress asigna desde una dirección (ceros a la izquierda).
func (z *Word) SetAddress(a types.Address) *Word { return z.SetBytes(a[:]) }

// ToBig devuelve el valor sin signo como big.Int.
func (z *Word) ToBig() *big.Int {
	b := z.Bytes32()
	return new(big.Int).SetBytes(b[:])
}

// ToSignedBig devuelve el valor interpretado en complemento a dos.
func (z *Word) ToSignedBig() *big.Int {
	v := z.ToBig()
	if z.isNeg() {
		v.Sub(v, two256)
	}
	return v
}

// ToAmount convierte a Amount (siempre cabe: ambos son de 256 bits).
func (z *Word) ToAmount() types.Amount { return types.MustAmountFromBig(z.ToBig()) }

// IsZero informa si la palabra es cero.
func (z *Word) IsZero() bool { return z[0]|z[1]|z[2]|z[3] == 0 }

// IsUint64 informa si el valor cabe en 64 bits.
func (z *Word) IsUint64() bool { return z[1]|z[2]|z[3] == 0 }

// Uint64 devuelve el limb bajo (truncando).
func (z *Word) Uint64() uint64 { return z[0] }

// Uint64WithOverflow devuelve el limb bajo y si hubo truncamiento.
func (z *Word) Uint64WithOverflow() (uint64, bool) { return z[0], !z.IsUint64() }

// BitLen devuelve el número de bits significativos.
func (z *Word) BitLen() int {
	for i := 3; i >= 0; i-- {
		if z[i] != 0 {
			return i*64 + bits.Len64(z[i])
		}
	}
	return 0
}

// ByteLen devuelve el número de bytes significativos.
func (z *Word) ByteLen() int { return (z.BitLen() + 7) / 8 }

// isNeg informa si el bit de signo (bit 255) está activo.
func (z *Word) isNeg() bool { return z[3]>>63 == 1 }

// Cmp compara sin signo: -1, 0 ó 1.
func (z *Word) Cmp(x *Word) int {
	for i := 3; i >= 0; i-- {
		if z[i] < x[i] {
			return -1
		}
		if z[i] > x[i] {
			return 1
		}
	}
	return 0
}

// Eq informa si z == x.
func (z *Word) Eq(x *Word) bool { return *z == *x }

// Lt informa si z < x (sin signo).
func (z *Word) Lt(x *Word) bool { return z.Cmp(x) < 0 }

// Gt informa si z > x (sin signo).
func (z *Word) Gt(x *Word) bool { return z.Cmp(x) > 0 }

// Slt informa si z < x interpretando ambos con signo.
func (z *Word) Slt(x *Word) bool {
	zn, xn := z.isNeg(), x.isNeg()
	if zn != xn {
		return zn // el negativo es el menor
	}
	return z.Lt(x) // mismo signo: el orden sin signo coincide
}

// Sgt informa si z > x con signo.
func (z *Word) Sgt(x *Word) bool { return x.Slt(z) }

// Add asigna z = x + y (mod 2^256).
func (z *Word) Add(x, y *Word) *Word {
	var c uint64
	z[0], c = bits.Add64(x[0], y[0], 0)
	z[1], c = bits.Add64(x[1], y[1], c)
	z[2], c = bits.Add64(x[2], y[2], c)
	z[3], _ = bits.Add64(x[3], y[3], c)
	return z
}

// AddOverflow asigna z = x + y e informa si hubo desbordamiento.
func (z *Word) AddOverflow(x, y *Word) (*Word, bool) {
	var c uint64
	z[0], c = bits.Add64(x[0], y[0], 0)
	z[1], c = bits.Add64(x[1], y[1], c)
	z[2], c = bits.Add64(x[2], y[2], c)
	z[3], c = bits.Add64(x[3], y[3], c)
	return z, c != 0
}

// Sub asigna z = x - y (mod 2^256).
func (z *Word) Sub(x, y *Word) *Word {
	var b uint64
	z[0], b = bits.Sub64(x[0], y[0], 0)
	z[1], b = bits.Sub64(x[1], y[1], b)
	z[2], b = bits.Sub64(x[2], y[2], b)
	z[3], _ = bits.Sub64(x[3], y[3], b)
	return z
}

// Neg asigna z = -x (complemento a dos).
func (z *Word) Neg(x *Word) *Word { return z.Sub(&Word{}, x) }

// Mul asigna z = x * y (mod 2^256) mediante multiplicación escolar de
// limbs, descartando los productos parciales que caen por encima de 2^256.
func (z *Word) Mul(x, y *Word) *Word {
	var res Word
	for i := 0; i < 4; i++ {
		if x[i] == 0 {
			continue
		}
		var carry uint64
		for j := 0; i+j < 4; j++ {
			hi, lo := bits.Mul64(x[i], y[j])
			var c uint64
			lo, c = bits.Add64(lo, res[i+j], 0)
			hi += c
			lo, c = bits.Add64(lo, carry, 0)
			hi += c
			res[i+j] = lo
			carry = hi
		}
	}
	*z = res
	return z
}

// Div asigna z = x / y; la EVM define x / 0 = 0.
func (z *Word) Div(x, y *Word) *Word {
	if y.IsZero() || y.Gt(x) {
		return z.Clear()
	}
	if x.IsUint64() { // camino rápido: ambos caben en 64 bits
		return z.SetUint64(x[0] / y[0])
	}
	return z.SetFromBig(new(big.Int).Quo(x.ToBig(), y.ToBig()))
}

// Mod asigna z = x mod y; la EVM define x mod 0 = 0.
func (z *Word) Mod(x, y *Word) *Word {
	if y.IsZero() {
		return z.Clear()
	}
	if x.Lt(y) {
		return z.Set(x)
	}
	if x.IsUint64() {
		return z.SetUint64(x[0] % y[0])
	}
	return z.SetFromBig(new(big.Int).Rem(x.ToBig(), y.ToBig()))
}

// SDiv asigna la división con signo truncada hacia cero. Casos especiales de
// la EVM: división por cero = 0 y (-2^255) / (-1) = -2^255 (desborda).
func (z *Word) SDiv(x, y *Word) *Word {
	if y.IsZero() {
		return z.Clear()
	}
	return z.SetFromBig(new(big.Int).Quo(x.ToSignedBig(), y.ToSignedBig()))
}

// SMod asigna el resto con signo (el signo sigue al dividendo, como en
// Solidity); módulo por cero = 0.
func (z *Word) SMod(x, y *Word) *Word {
	if y.IsZero() {
		return z.Clear()
	}
	return z.SetFromBig(new(big.Int).Rem(x.ToSignedBig(), y.ToSignedBig()))
}

// AddMod asigna z = (x + y) mod m con precisión arbitraria (sin perder el
// acarreo de 257 bits); m = 0 da 0.
func (z *Word) AddMod(x, y, m *Word) *Word {
	if m.IsZero() {
		return z.Clear()
	}
	s := new(big.Int).Add(x.ToBig(), y.ToBig())
	return z.SetFromBig(s.Mod(s, m.ToBig()))
}

// MulMod asigna z = (x * y) mod m con precisión de 512 bits; m = 0 da 0.
func (z *Word) MulMod(x, y, m *Word) *Word {
	if m.IsZero() {
		return z.Clear()
	}
	p := new(big.Int).Mul(x.ToBig(), y.ToBig())
	return z.SetFromBig(p.Mod(p, m.ToBig()))
}

// Exp asigna z = base^exp mod 2^256 por exponenciación binaria.
func (z *Word) Exp(base, exp *Word) *Word {
	res := Word{1}
	b := *base
	n := exp.BitLen()
	for i := 0; i < n; i++ {
		if (exp[i/64]>>(uint(i)%64))&1 == 1 {
			res.Mul(&res, &b)
		}
		b.Mul(&b, &b)
	}
	*z = res
	return z
}

// SignExtend extiende el signo de x desde el byte número `back` (0 = byte
// menos significativo). Si back >= 31 x queda igual.
func (z *Word) SignExtend(back, x *Word) *Word {
	if !back.IsUint64() || back[0] >= 31 {
		return z.Set(x)
	}
	bit := uint(back[0]*8 + 7) // posición del bit de signo
	limb, off := bit/64, bit%64
	neg := (x[limb]>>off)&1 == 1
	*z = *x
	// Máscara de los bits por encima de `bit` dentro del limb.
	mask := ^uint64(0) << off << 1
	if off == 63 {
		mask = 0
	}
	if neg {
		z[limb] |= mask
		for i := limb + 1; i < 4; i++ {
			z[i] = ^uint64(0)
		}
	} else {
		z[limb] &^= mask
		for i := limb + 1; i < 4; i++ {
			z[i] = 0
		}
	}
	return z
}

// And, Or, Xor y Not son las operaciones de bits habituales.
func (z *Word) And(x, y *Word) *Word {
	z[0], z[1], z[2], z[3] = x[0]&y[0], x[1]&y[1], x[2]&y[2], x[3]&y[3]
	return z
}

// Or asigna z = x | y.
func (z *Word) Or(x, y *Word) *Word {
	z[0], z[1], z[2], z[3] = x[0]|y[0], x[1]|y[1], x[2]|y[2], x[3]|y[3]
	return z
}

// Xor asigna z = x ^ y.
func (z *Word) Xor(x, y *Word) *Word {
	z[0], z[1], z[2], z[3] = x[0]^y[0], x[1]^y[1], x[2]^y[2], x[3]^y[3]
	return z
}

// Not asigna z = ^x.
func (z *Word) Not(x *Word) *Word {
	z[0], z[1], z[2], z[3] = ^x[0], ^x[1], ^x[2], ^x[3]
	return z
}

// Lsh asigna z = x << n (n >= 256 da cero).
func (z *Word) Lsh(x *Word, n uint) *Word {
	if n >= 256 {
		return z.Clear()
	}
	var r Word
	limbs, off := n/64, n%64
	for i := 3; i >= int(limbs); i-- {
		v := x[i-int(limbs)] << off
		if off != 0 && i-int(limbs)-1 >= 0 {
			v |= x[i-int(limbs)-1] >> (64 - off)
		}
		r[i] = v
	}
	*z = r
	return z
}

// Rsh asigna z = x >> n lógico (n >= 256 da cero).
func (z *Word) Rsh(x *Word, n uint) *Word {
	if n >= 256 {
		return z.Clear()
	}
	var r Word
	limbs, off := n/64, n%64
	for i := 0; i < 4-int(limbs); i++ {
		v := x[i+int(limbs)] >> off
		if off != 0 && i+int(limbs)+1 < 4 {
			v |= x[i+int(limbs)+1] << (64 - off)
		}
		r[i] = v
	}
	*z = r
	return z
}

// SRsh asigna el desplazamiento aritmético (conserva el signo).
func (z *Word) SRsh(x *Word, n uint) *Word {
	neg := x.isNeg()
	if n >= 256 {
		if neg {
			*z = Word{^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)}
			return z
		}
		return z.Clear()
	}
	z.Rsh(x, n)
	if neg && n > 0 {
		// Rellenamos con unos los n bits superiores.
		var ones Word
		ones.Not(&Word{})
		ones.Lsh(&ones, 256-n)
		z.Or(z, &ones)
	}
	return z
}

// Byte devuelve en z el byte número n de x contando desde el más
// significativo (n >= 32 da 0), semántica del opcode BYTE.
func (z *Word) Byte(n, x *Word) *Word {
	if !n.IsUint64() || n[0] >= 32 {
		return z.Clear()
	}
	b := x.Bytes32()
	return z.SetUint64(uint64(b[n[0]]))
}

// String devuelve el valor decimal.
func (z *Word) String() string { return z.ToBig().String() }

// Hex devuelve el valor en hexadecimal con prefijo 0x.
func (z *Word) Hex() string { return "0x" + z.ToBig().Text(16) }

// Format implementa fmt.Formatter de forma sencilla (%v, %s, %d, %x).
func (z *Word) Format(s fmt.State, c rune) {
	switch c {
	case 'x':
		fmt.Fprint(s, z.ToBig().Text(16))
	default:
		fmt.Fprint(s, z.String())
	}
}

// ---------------------------------------------------------------------------
// Pila
// ---------------------------------------------------------------------------

// Stack es la pila de operandos de un marco de ejecución. Las comprobaciones
// de desbordamiento/subdesbordamiento las hace el intérprete antes de
// ejecutar cada instrucción (usando minStack/maxStack de la tabla de saltos),
// por lo que los métodos aquí no las repiten.
type Stack struct {
	data []Word
}

// stackPool recicla pilas entre llamadas para reducir la presión sobre el GC.
var stackPool = sync.Pool{New: func() any { return &Stack{data: make([]Word, 0, 16)} }}

// newStack obtiene una pila vacía del pool.
func newStack() *Stack { return stackPool.Get().(*Stack) }

// returnStack devuelve la pila al pool.
func returnStack(s *Stack) {
	s.data = s.data[:0]
	stackPool.Put(s)
}

// NewStack crea una pila vacía (API pública para pruebas y trazadores).
func NewStack() *Stack { return &Stack{} }

// Data devuelve el contenido (el último elemento es la cima).
func (s *Stack) Data() []Word { return s.data }

// push apila una copia del valor.
func (s *Stack) push(v *Word) { s.data = append(s.data, *v) }

// Push es la versión exportada de push.
func (s *Stack) Push(v *Word) { s.push(v) }

// pop desapila y devuelve la cima.
func (s *Stack) pop() Word {
	v := s.data[len(s.data)-1]
	s.data = s.data[:len(s.data)-1]
	return v
}

// Pop es la versión exportada de pop.
func (s *Stack) Pop() Word { return s.pop() }

// peek devuelve un puntero a la cima (para modificarla en sitio).
func (s *Stack) peek() *Word { return &s.data[len(s.data)-1] }

// Back devuelve un puntero al n-ésimo elemento desde la cima (0 = cima).
func (s *Stack) Back(n int) *Word { return &s.data[len(s.data)-n-1] }

// Len devuelve el número de elementos.
func (s *Stack) Len() int { return len(s.data) }

// swap intercambia la cima con el elemento n posiciones por debajo.
func (s *Stack) swap(n int) {
	top := len(s.data) - 1
	s.data[top], s.data[top-n] = s.data[top-n], s.data[top]
}

// dup duplica el n-ésimo elemento (1 = cima) y lo apila.
func (s *Stack) dup(n int) { s.data = append(s.data, s.data[len(s.data)-n]) }
