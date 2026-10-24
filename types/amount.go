package types

// Este archivo define Amount, el tipo para cantidades de la moneda nativa
// (balances, valores transferidos, precios de gas y comisiones).
//
// # Diseño
//
// Amount envuelve un *big.Int con semántica de VALOR inmutable: todas las
// operaciones devuelven un Amount nuevo y nunca modifican al receptor. Esto
// evita la clase de bugs típica de big.Int, donde dos estructuras comparten
// el mismo puntero y una modificación "se filtra" a la otra (por ejemplo, un
// balance del estado y el valor de una transacción).
//
// El valor cero de Amount (Amount{}) es válido y representa 0.
//
// El rango admitido es [0, 2^256-1], igual que una palabra de la EVM. Las
// operaciones "Checked*" devuelven error si el resultado sale de rango; las
// operaciones simples (Add, Sub, ...) están pensadas para cálculos internos
// donde los invariantes ya garantizan el rango, y entran en pánico si se viola
// (es un bug, no una entrada externa).

import (
	"fmt"
	"math/big"
	"strings"
)

// maxAmount es 2^256-1, el máximo representable.
var maxAmount = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))

// Amount es una cantidad no negativa de wei, de hasta 256 bits.
type Amount struct {
	// i es nil para el cero; nunca se expone ni se modifica tras construir.
	i *big.Int
}

// NewAmount crea un Amount a partir de un uint64 de wei.
func NewAmount(v uint64) Amount {
	if v == 0 {
		return Amount{}
	}
	return Amount{i: new(big.Int).SetUint64(v)}
}

// AmountFromBig crea un Amount copiando b. Devuelve error si b es negativo o
// supera 2^256-1.
func AmountFromBig(b *big.Int) (Amount, error) {
	if b == nil || b.Sign() == 0 {
		return Amount{}, nil
	}
	if b.Sign() < 0 {
		return Amount{}, ErrAmountUnderflow
	}
	if b.Cmp(maxAmount) > 0 {
		return Amount{}, ErrAmountOverflow
	}
	return Amount{i: new(big.Int).Set(b)}, nil
}

// MustAmountFromBig es como AmountFromBig pero entra en pánico ante error.
func MustAmountFromBig(b *big.Int) Amount {
	a, err := AmountFromBig(b)
	if err != nil {
		panic(err)
	}
	return a
}

// AmountFromBytes interpreta b como entero big-endian sin signo (máx. 32 bytes).
func AmountFromBytes(b []byte) (Amount, error) {
	if len(b) > 32 {
		return Amount{}, ErrAmountOverflow
	}
	return AmountFromBig(new(big.Int).SetBytes(b))
}

// EtherAmount devuelve n unidades enteras de la moneda (n * 10^18 wei).
func EtherAmount(n uint64) Amount {
	return Amount{i: new(big.Int).Mul(new(big.Int).SetUint64(n), new(big.Int).SetUint64(Ether))}
}

// GWeiAmount devuelve n gwei (n * 10^9 wei).
func GWeiAmount(n uint64) Amount {
	return Amount{i: new(big.Int).Mul(new(big.Int).SetUint64(n), new(big.Int).SetUint64(GWei))}
}

// ParseAmount parsea una cantidad en wei, en decimal ("1000") o hexadecimal
// ("0x3e8"). También acepta sufijos de unidad legibles: "1.5ether", "20gwei".
func ParseAmount(s string) (Amount, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Amount{}, ErrInvalidAmount
	}
	if has0xPrefix(s) {
		b, ok := new(big.Int).SetString(s[2:], 16)
		if !ok {
			return Amount{}, fmt.Errorf("%w: %q", ErrInvalidAmount, s)
		}
		return AmountFromBig(b)
	}
	// Unidades opcionales: se convierte a wei usando aritmética racional
	// exacta para no perder precisión con decimales.
	unit := big.NewInt(1)
	lower := strings.ToLower(s)
	switch {
	case strings.HasSuffix(lower, "ether"):
		unit = new(big.Int).SetUint64(Ether)
		s = strings.TrimSpace(s[:len(s)-len("ether")])
	case strings.HasSuffix(lower, "gwei"):
		unit = new(big.Int).SetUint64(GWei)
		s = strings.TrimSpace(s[:len(s)-len("gwei")])
	case strings.HasSuffix(lower, "wei"):
		s = strings.TrimSpace(s[:len(s)-len("wei")])
	}
	r, ok := new(big.Rat).SetString(s)
	if !ok {
		return Amount{}, fmt.Errorf("%w: %q", ErrInvalidAmount, s)
	}
	r.Mul(r, new(big.Rat).SetInt(unit))
	if !r.IsInt() {
		// Fracción de wei: no representable.
		return Amount{}, fmt.Errorf("%w: fracción de wei en %q", ErrInvalidAmount, s)
	}
	return AmountFromBig(r.Num())
}

// big devuelve el entero interno o un cero compartido (sólo lectura).
func (a Amount) big() *big.Int {
	if a.i == nil {
		return new(big.Int)
	}
	return a.i
}

// Big devuelve una COPIA del valor como *big.Int; modificarla no afecta a a.
func (a Amount) Big() *big.Int { return new(big.Int).Set(a.big()) }

// IsZero informa si el monto es cero.
func (a Amount) IsZero() bool { return a.i == nil || a.i.Sign() == 0 }

// Sign devuelve 0 si es cero y 1 si es positivo (nunca es negativo).
func (a Amount) Sign() int { return a.big().Sign() }

// Cmp compara a con b (-1, 0, 1).
func (a Amount) Cmp(b Amount) int { return a.big().Cmp(b.big()) }

// Eq informa si a == b.
func (a Amount) Eq(b Amount) bool { return a.Cmp(b) == 0 }

// Lt informa si a < b.
func (a Amount) Lt(b Amount) bool { return a.Cmp(b) < 0 }

// Gt informa si a > b.
func (a Amount) Gt(b Amount) bool { return a.Cmp(b) > 0 }

// IsUint64 informa si el monto entra en un uint64.
func (a Amount) IsUint64() bool { return a.big().IsUint64() }

// Uint64 devuelve el monto como uint64 (truncado si no entra; verificar antes
// con IsUint64).
func (a Amount) Uint64() uint64 { return a.big().Uint64() }

// fromResult valida el rango de r y lo envuelve.
func fromResult(r *big.Int) (Amount, error) {
	if r.Sign() < 0 {
		return Amount{}, ErrAmountUnderflow
	}
	if r.Cmp(maxAmount) > 0 {
		return Amount{}, ErrAmountOverflow
	}
	if r.Sign() == 0 {
		return Amount{}, nil
	}
	return Amount{i: r}, nil
}

// mustResult es fromResult que entra en pánico si se viola el rango.
func mustResult(r *big.Int) Amount {
	a, err := fromResult(r)
	if err != nil {
		panic(err)
	}
	return a
}

// CheckedAdd devuelve a+b o ErrAmountOverflow.
func (a Amount) CheckedAdd(b Amount) (Amount, error) {
	return fromResult(new(big.Int).Add(a.big(), b.big()))
}

// CheckedSub devuelve a-b o ErrAmountUnderflow si b > a.
func (a Amount) CheckedSub(b Amount) (Amount, error) {
	return fromResult(new(big.Int).Sub(a.big(), b.big()))
}

// CheckedMul devuelve a*b o ErrAmountOverflow.
func (a Amount) CheckedMul(b Amount) (Amount, error) {
	return fromResult(new(big.Int).Mul(a.big(), b.big()))
}

// Add devuelve a+b; entra en pánico si desborda.
func (a Amount) Add(b Amount) Amount { return mustResult(new(big.Int).Add(a.big(), b.big())) }

// Sub devuelve a-b; entra en pánico si el resultado sería negativo.
func (a Amount) Sub(b Amount) Amount { return mustResult(new(big.Int).Sub(a.big(), b.big())) }

// Mul devuelve a*b; entra en pánico si desborda.
func (a Amount) Mul(b Amount) Amount { return mustResult(new(big.Int).Mul(a.big(), b.big())) }

// MulUint64 devuelve a*n; entra en pánico si desborda. Caso típico: gas * precio.
func (a Amount) MulUint64(n uint64) Amount {
	return mustResult(new(big.Int).Mul(a.big(), new(big.Int).SetUint64(n)))
}

// Div devuelve la división entera a/b (truncada). Entra en pánico si b es 0.
func (a Amount) Div(b Amount) Amount {
	if b.IsZero() {
		panic("types: división de Amount por cero")
	}
	return mustResult(new(big.Int).Quo(a.big(), b.big()))
}

// DivUint64 devuelve a/n (truncada). Entra en pánico si n es 0.
func (a Amount) DivUint64(n uint64) Amount { return a.Div(NewAmount(n)) }

// Min devuelve el menor entre a y b.
func (a Amount) Min(b Amount) Amount {
	if a.Cmp(b) <= 0 {
		return a
	}
	return b
}

// Max devuelve el mayor entre a y b.
func (a Amount) Max(b Amount) Amount {
	if a.Cmp(b) >= 0 {
		return a
	}
	return b
}

// Bytes devuelve el valor en big-endian sin ceros a la izquierda (vacío para 0).
func (a Amount) Bytes() []byte { return a.big().Bytes() }

// Bytes32 devuelve el valor como palabra de 32 bytes (formato de la EVM).
func (a Amount) Bytes32() [32]byte {
	var out [32]byte
	a.big().FillBytes(out[:])
	return out
}

// String devuelve el valor en decimal (wei).
func (a Amount) String() string { return a.big().String() }

// Hex devuelve el valor como cantidad hexadecimal JSON-RPC ("0x0", "0x1a").
func (a Amount) Hex() string { return "0x" + a.big().Text(16) }

// FormatEther devuelve el valor en unidades enteras con hasta 18 decimales,
// sin ceros finales (p. ej. "1.5"). Sólo para presentación.
func (a Amount) FormatEther() string {
	r := new(big.Rat).SetFrac(a.big(), new(big.Int).SetUint64(Ether))
	s := r.FloatString(Decimals)
	s = strings.TrimRight(s, "0")
	return strings.TrimSuffix(s, ".")
}

// MarshalText serializa en decimal: es legible en el génesis y no pierde
// precisión (JSON numérico perdería precisión en valores > 2^53).
func (a Amount) MarshalText() ([]byte, error) { return []byte(a.String()), nil }

// UnmarshalText acepta decimal, hexadecimal o valores con unidad (ver ParseAmount).
func (a *Amount) UnmarshalText(text []byte) error {
	v, err := ParseAmount(string(text))
	if err != nil {
		return err
	}
	*a = v
	return nil
}

// EncodeRLP codifica el monto como entero RLP canónico.
func (a Amount) EncodeRLP() []byte { return EncodeBig(a.big()) }

// DecodeAmountRLP decodifica un monto desde un ítem RLP.
func DecodeAmountRLP(it RLPItem) (Amount, error) {
	b, err := it.Big()
	if err != nil {
		return Amount{}, err
	}
	return AmountFromBig(b)
}
