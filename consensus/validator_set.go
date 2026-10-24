package consensus

// Este archivo define el conjunto de validadores de una época: una lista
// ordenada por dirección con su clave pública BLS y su poder de voto, más
// las cuentas de quórum BFT. También define Bitmap, la representación
// compacta de "qué validadores firmaron" que usan QCs y TCs.
//
// Con poder total N, el protocolo tolera f = ⌊(N-1)/3⌋ de poder bizantino y
// exige un quórum de ⌊2N/3⌋+1: dos quórums cualesquiera se solapan en más
// de N/3 de poder, luego en al menos un validador honesto.

import (
	"bytes"
	"errors"
	"fmt"
	"math/bits"
	"sort"

	"github.com/l1/l1/crypto"
	"github.com/l1/l1/types"
)

// Errores del conjunto de validadores.
var (
	ErrEmptyValidatorSet  = errors.New("consenso: conjunto de validadores vacío")
	ErrDuplicateValidator = errors.New("consenso: validador duplicado")
	ErrZeroPower          = errors.New("consenso: validador con poder 0")
	ErrPowerOverflow      = errors.New("consenso: desbordamiento del poder total")
	ErrBitmapSize         = errors.New("consenso: tamaño de bitmap incorrecto")
)

// MaxTotalPower acota el poder total para que 2·total no desborde uint64.
const MaxTotalPower = uint64(1) << 62

// Validator es un miembro del conjunto.
type Validator struct {
	// Address es la cuenta del validador (la de registro en staking y la
	// que cobra recompensas).
	Address types.Address
	// PubKey es su clave pública BLS para votos, propuestas y timeouts.
	PubKey *crypto.BLSPublicKey
	// Power es el poder de voto (stake normalizado).
	Power uint64
}

// ValidatorSet es inmutable una vez construido: todas las operaciones son
// seguras para uso concurrente.
type ValidatorSet struct {
	vals   []*Validator
	byAddr map[types.Address]int
	total  uint64
	hash   types.Hash
}

// NewValidatorSet valida y ordena la lista (por dirección ascendente, para
// que el índice de cada validador sea canónico) y precalcula totales y hash.
func NewValidatorSet(vals []*Validator) (*ValidatorSet, error) {
	if len(vals) == 0 {
		return nil, ErrEmptyValidatorSet
	}
	cp := make([]*Validator, len(vals))
	for i, v := range vals {
		if v == nil || v.PubKey == nil {
			return nil, fmt.Errorf("consenso: validador %d sin clave", i)
		}
		if v.Power == 0 {
			return nil, fmt.Errorf("%w: %s", ErrZeroPower, v.Address.Hex())
		}
		c := *v
		cp[i] = &c
	}
	sort.Slice(cp, func(i, j int) bool { return bytes.Compare(cp[i].Address[:], cp[j].Address[:]) < 0 })
	s := &ValidatorSet{vals: cp, byAddr: make(map[types.Address]int, len(cp))}
	for i, v := range cp {
		if _, dup := s.byAddr[v.Address]; dup {
			return nil, fmt.Errorf("%w: %s", ErrDuplicateValidator, v.Address.Hex())
		}
		s.byAddr[v.Address] = i
		sum, carry := bits.Add64(s.total, v.Power, 0)
		if carry != 0 || sum > MaxTotalPower {
			return nil, ErrPowerOverflow
		}
		s.total = sum
	}
	s.hash = crypto.Keccak256Hash(s.EncodeRLP())
	return s, nil
}

// Size es el número de validadores.
func (s *ValidatorSet) Size() int { return len(s.vals) }

// Validators devuelve una copia de la lista ordenada.
func (s *ValidatorSet) Validators() []*Validator {
	out := make([]*Validator, len(s.vals))
	copy(out, s.vals)
	return out
}

// ByIndex devuelve el validador de índice i (nil si fuera de rango).
func (s *ValidatorSet) ByIndex(i int) *Validator {
	if i < 0 || i >= len(s.vals) {
		return nil
	}
	return s.vals[i]
}

// ByAddress devuelve índice y validador de una dirección (-1, nil si no
// pertenece).
func (s *ValidatorSet) ByAddress(a types.Address) (int, *Validator) {
	i, ok := s.byAddr[a]
	if !ok {
		return -1, nil
	}
	return i, s.vals[i]
}

// Contains informa si la dirección es validador.
func (s *ValidatorSet) Contains(a types.Address) bool { _, ok := s.byAddr[a]; return ok }

// TotalPower es la suma del poder de voto.
func (s *ValidatorSet) TotalPower() uint64 { return s.total }

// QuorumPower es el poder mínimo de un quórum: ⌊2N/3⌋ + 1.
func (s *ValidatorSet) QuorumPower() uint64 { return s.total*2/3 + 1 }

// ValidityPower es el poder mínimo que garantiza al menos un honesto:
// f + 1 = ⌊(N-1)/3⌋ + 1. Se usa para sumarse a un timeout ajeno.
func (s *ValidatorSet) ValidityPower() uint64 { return (s.total-1)/3 + 1 }

// HasQuorum informa si power alcanza el quórum.
func (s *ValidatorSet) HasQuorum(power uint64) bool { return power >= s.QuorumPower() }

// Hash es el compromiso que se escribe en Header.ValidatorsHash.
func (s *ValidatorSet) Hash() types.Hash { return s.hash }

// EncodeRLP codifica el conjunto como lista de [dirección, clave, poder].
func (s *ValidatorSet) EncodeRLP() []byte {
	items := make([][]byte, len(s.vals))
	for i, v := range s.vals {
		items[i] = types.EncodeList(types.EncodeBytes(v.Address[:]), types.EncodeBytes(v.PubKey.Bytes()), types.EncodeUint(v.Power))
	}
	return types.EncodeList(items...)
}

// DecodeValidatorSet es la inversa de EncodeRLP.
func DecodeValidatorSet(b []byte) (*ValidatorSet, error) {
	it, err := types.DecodeRLP(b)
	if err != nil {
		return nil, err
	}
	items, err := it.Items()
	if err != nil {
		return nil, err
	}
	vals := make([]*Validator, 0, len(items))
	for _, e := range items {
		f, err := e.ListN(3)
		if err != nil {
			return nil, err
		}
		addr, err := f[0].Address()
		if err != nil {
			return nil, err
		}
		kb, err := f[1].Bytes()
		if err != nil {
			return nil, err
		}
		pk, err := crypto.BLSPublicKeyFromBytes(kb)
		if err != nil {
			return nil, err
		}
		pw, err := f[2].Uint64()
		if err != nil {
			return nil, err
		}
		vals = append(vals, &Validator{Address: addr, PubKey: pk, Power: pw})
	}
	return NewValidatorSet(vals)
}

// PowerOf suma el poder de los validadores marcados en el bitmap.
func (s *ValidatorSet) PowerOf(bm Bitmap) (uint64, error) {
	if bm.Len() != len(s.vals) {
		return 0, ErrBitmapSize
	}
	var p uint64
	for _, i := range bm.Indices() {
		p += s.vals[i].Power
	}
	return p, nil
}

// PubKeysOf devuelve las claves de los firmantes del bitmap, en orden de
// índice.
func (s *ValidatorSet) PubKeysOf(bm Bitmap) ([]*crypto.BLSPublicKey, error) {
	if bm.Len() != len(s.vals) {
		return nil, ErrBitmapSize
	}
	idx := bm.Indices()
	out := make([]*crypto.BLSPublicKey, len(idx))
	for k, i := range idx {
		out[k] = s.vals[i].PubKey
	}
	return out, nil
}

// String resume el conjunto para logs.
func (s *ValidatorSet) String() string {
	return fmt.Sprintf("ValidatorSet{n=%d total=%d quorum=%d hash=%s}", len(s.vals), s.total, s.QuorumPower(), s.hash.Hex())
}

// ---------------------------------------------------------------------------
// Bitmap
// ---------------------------------------------------------------------------

// Bitmap marca un subconjunto de índices de validadores. Se guarda como n
// (número de bits) más los bytes, con el bit i en el byte i/8, posición i%8
// (LSB primero).
type Bitmap struct {
	n    int
	bits []byte
}

// NewBitmap crea un bitmap vacío de n bits.
func NewBitmap(n int) Bitmap { return Bitmap{n: n, bits: make([]byte, (n+7)/8)} }

// Len es el número de bits.
func (b Bitmap) Len() int { return b.n }

// Set marca el índice i (ignora índices fuera de rango).
func (b Bitmap) Set(i int) {
	if i >= 0 && i < b.n {
		b.bits[i/8] |= 1 << (i % 8)
	}
}

// Get consulta el índice i.
func (b Bitmap) Get(i int) bool {
	return i >= 0 && i < b.n && b.bits[i/8]&(1<<(i%8)) != 0
}

// Count es el número de bits marcados.
func (b Bitmap) Count() int {
	c := 0
	for _, x := range b.bits {
		c += bits.OnesCount8(x)
	}
	return c
}

// Indices devuelve los índices marcados en orden ascendente.
func (b Bitmap) Indices() []int {
	out := make([]int, 0, b.Count())
	for i := 0; i < b.n; i++ {
		if b.Get(i) {
			out = append(out, i)
		}
	}
	return out
}

// Copy devuelve una copia independiente.
func (b Bitmap) Copy() Bitmap {
	return Bitmap{n: b.n, bits: append([]byte(nil), b.bits...)}
}

// EncodeRLP codifica [n, bytes].
func (b Bitmap) EncodeRLP() []byte {
	return types.EncodeList(types.EncodeUint(uint64(b.n)), types.EncodeBytes(b.bits))
}

// decodeBitmap decodifica y valida que no haya bits más allá de n (para que
// la codificación sea canónica y el hash del QC único).
func decodeBitmap(it types.RLPItem) (Bitmap, error) {
	f, err := it.ListN(2)
	if err != nil {
		return Bitmap{}, err
	}
	n, err := f[0].Uint64()
	if err != nil {
		return Bitmap{}, err
	}
	if n > 1<<16 {
		return Bitmap{}, ErrBitmapSize
	}
	raw, err := f[1].BytesCopy()
	if err != nil {
		return Bitmap{}, err
	}
	if len(raw) != (int(n)+7)/8 {
		return Bitmap{}, ErrBitmapSize
	}
	if n%8 != 0 && len(raw) > 0 && raw[len(raw)-1]>>(n%8) != 0 {
		return Bitmap{}, fmt.Errorf("%w: bits fuera de rango", ErrBitmapSize)
	}
	return Bitmap{n: int(n), bits: raw}, nil
}
