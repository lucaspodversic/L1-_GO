package types

// Este archivo implementa los códecs básicos del protocolo:
//
//  1. RLP (Recursive Length Prefix), la serialización canónica usada para
//     hashear y persistir cabeceras, transacciones, cuentas, nodos del trie,
//     recibos, etc. Es idéntica a la de Ethereum (Yellow Paper, apéndice B).
//  2. Utilidades hexadecimales con prefijo "0x" (para JSON, CLI y RPC).
//
// # Por qué un RLP propio y sin reflexión
//
// En lugar de un codificador basado en reflect (como el de go-ethereum) se usa
// una API explícita: cada tipo arma su lista con EncodeList(...) y se decodifica
// recorriendo un RLPItem. Es más verboso pero:
//   - el orden y tipo de cada campo queda a la vista (importante en consenso),
//   - no hay sorpresas con campos agregados a un struct,
//   - es fácil de auditar y de "fuzzear".
//
// # Reglas de RLP (resumen)
//
//   - Un byte único en [0x00, 0x7f] se codifica a sí mismo.
//   - Un string de 0..55 bytes: 0x80+len, seguido del contenido.
//   - Un string de más de 55 bytes: 0xb7+len(len), largo big-endian, contenido.
//   - Una lista cuyo payload mide 0..55 bytes: 0xc0+len, seguido del payload.
//   - Una lista más larga: 0xf7+len(len), largo big-endian, payload.
//
// Los enteros se codifican como strings big-endian SIN ceros a la izquierda
// (el cero es el string vacío, 0x80). El decodificador exige la forma canónica
// en todos los casos: así cada valor tiene exactamente una codificación y por
// lo tanto un único hash.

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// Codificación RLP
// ---------------------------------------------------------------------------

// RLPEmptyString es la codificación de un string vacío (y del entero 0).
var RLPEmptyString = []byte{0x80}

// RLPEmptyList es la codificación de una lista vacía.
var RLPEmptyList = []byte{0xc0}

// encodeLength arma el prefijo de largo para un payload de tamaño n, usando
// offset 0x80 (strings) o 0xc0 (listas).
func encodeLength(n int, offset byte) []byte {
	if n <= 55 {
		// Forma corta: el largo va embebido en el primer byte.
		return []byte{offset + byte(n)}
	}
	// Forma larga: primero cuántos bytes ocupa el largo, después el largo.
	lenBytes := putUintBigEndian(uint64(n))
	out := make([]byte, 0, 1+len(lenBytes))
	out = append(out, offset+55+byte(len(lenBytes)))
	return append(out, lenBytes...)
}

// putUintBigEndian devuelve u en big-endian sin ceros a la izquierda.
// Para u == 0 devuelve un slice vacío (forma canónica de RLP).
func putUintBigEndian(u uint64) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], u)
	i := 0
	for i < 8 && buf[i] == 0 {
		i++
	}
	return append([]byte(nil), buf[i:]...)
}

// EncodeBytes codifica un string de bytes arbitrario.
func EncodeBytes(b []byte) []byte {
	// Caso especial: un único byte < 0x80 se representa a sí mismo.
	if len(b) == 1 && b[0] < 0x80 {
		return []byte{b[0]}
	}
	prefix := encodeLength(len(b), 0x80)
	out := make([]byte, 0, len(prefix)+len(b))
	out = append(out, prefix...)
	return append(out, b...)
}

// EncodeString codifica un string de Go como bytes.
func EncodeString(s string) []byte { return EncodeBytes([]byte(s)) }

// EncodeUint codifica un entero sin signo en su forma canónica mínima.
func EncodeUint(u uint64) []byte {
	if u == 0 {
		return []byte{0x80}
	}
	return EncodeBytes(putUintBigEndian(u))
}

// EncodeBool codifica un booleano como entero 0/1 (convención de Ethereum).
func EncodeBool(b bool) []byte {
	if b {
		return EncodeUint(1)
	}
	return EncodeUint(0)
}

// EncodeBig codifica un entero grande no negativo. nil se trata como 0.
// Entra en pánico con negativos porque RLP no los representa: es un error de
// programación, no de entrada externa.
func EncodeBig(i *big.Int) []byte {
	if i == nil || i.Sign() == 0 {
		return []byte{0x80}
	}
	if i.Sign() < 0 {
		panic("rlp: no se pueden codificar enteros negativos")
	}
	return EncodeBytes(i.Bytes()) // Bytes() ya es big-endian sin ceros a la izquierda.
}

// EncodeList concatena elementos YA codificados y les antepone el prefijo de
// lista. Permite anidar libremente: EncodeList(EncodeUint(1), EncodeList(...)).
func EncodeList(items ...[]byte) []byte {
	size := 0
	for _, it := range items {
		size += len(it)
	}
	prefix := encodeLength(size, 0xc0)
	out := make([]byte, 0, len(prefix)+size)
	out = append(out, prefix...)
	for _, it := range items {
		out = append(out, it...)
	}
	return out
}

// ---------------------------------------------------------------------------
// Decodificación RLP
// ---------------------------------------------------------------------------

// RLPKind distingue strings (bytes) de listas.
type RLPKind uint8

const (
	// RLPString es un string de bytes (incluye enteros).
	RLPString RLPKind = iota
	// RLPList es una lista de elementos.
	RLPList
)

// RLPItem es un elemento RLP decodificado. Los slices apuntan al buffer
// original (no se copian): el llamador no debe modificar ese buffer mientras
// use el ítem, y debe copiar lo que quiera conservar.
type RLPItem struct {
	// Kind indica si es string o lista.
	Kind RLPKind
	// Data es el contenido del string (vacío para listas).
	Data []byte
	// List contiene los elementos hijos si Kind == RLPList.
	List []RLPItem
	// Raw es la codificación completa (prefijo + contenido) del ítem. Es útil
	// para nodos del trie embebidos, cuyo hash se calcula sobre lo codificado.
	Raw []byte
}

// DecodeRLP decodifica exactamente un elemento y exige que no sobren bytes.
func DecodeRLP(b []byte) (RLPItem, error) {
	it, rest, err := decodeItem(b, 0)
	if err != nil {
		return RLPItem{}, err
	}
	if len(rest) != 0 {
		return RLPItem{}, ErrRLPTrailing
	}
	return it, nil
}

// SplitRLP decodifica el primer elemento de b y devuelve el resto sin
// interpretar; útil para leer flujos de elementos concatenados.
func SplitRLP(b []byte) (RLPItem, []byte, error) { return decodeItem(b, 0) }

// decodeItem es el núcleo recursivo del decodificador. depth acota la
// recursión para que una entrada maliciosa no agote la pila.
func decodeItem(b []byte, depth int) (RLPItem, []byte, error) {
	if depth > MaxRLPDepth {
		return RLPItem{}, nil, ErrRLPTooDeep
	}
	if len(b) == 0 {
		return RLPItem{}, nil, ErrRLPTruncated
	}
	p := b[0]
	switch {
	case p < 0x80:
		// Byte único que se representa a sí mismo.
		return RLPItem{Kind: RLPString, Data: b[:1], Raw: b[:1]}, b[1:], nil

	case p <= 0xb7:
		// String corto.
		n := int(p - 0x80)
		if len(b) < 1+n {
			return RLPItem{}, nil, ErrRLPTruncated
		}
		data := b[1 : 1+n]
		// Canonicidad: un byte < 0x80 debió codificarse solo, sin prefijo.
		if n == 1 && data[0] < 0x80 {
			return RLPItem{}, nil, ErrRLPNonCanonical
		}
		return RLPItem{Kind: RLPString, Data: data, Raw: b[:1+n]}, b[1+n:], nil

	case p <= 0xbf:
		// String largo: el prefijo indica cuántos bytes ocupa el largo.
		ll := int(p - 0xb7)
		n, err := readLongLength(b[1:], ll)
		if err != nil {
			return RLPItem{}, nil, err
		}
		start := 1 + ll
		if uint64(len(b)-start) < n {
			return RLPItem{}, nil, ErrRLPTruncated
		}
		end := start + int(n)
		return RLPItem{Kind: RLPString, Data: b[start:end], Raw: b[:end]}, b[end:], nil

	case p <= 0xf7:
		// Lista corta.
		n := int(p - 0xc0)
		if len(b) < 1+n {
			return RLPItem{}, nil, ErrRLPTruncated
		}
		children, err := decodeChildren(b[1:1+n], depth)
		if err != nil {
			return RLPItem{}, nil, err
		}
		return RLPItem{Kind: RLPList, List: children, Raw: b[:1+n]}, b[1+n:], nil

	default:
		// Lista larga.
		ll := int(p - 0xf7)
		n, err := readLongLength(b[1:], ll)
		if err != nil {
			return RLPItem{}, nil, err
		}
		start := 1 + ll
		if uint64(len(b)-start) < n {
			return RLPItem{}, nil, ErrRLPTruncated
		}
		end := start + int(n)
		children, err := decodeChildren(b[start:end], depth)
		if err != nil {
			return RLPItem{}, nil, err
		}
		return RLPItem{Kind: RLPList, List: children, Raw: b[:end]}, b[end:], nil
	}
}

// readLongLength lee un largo big-endian de ll bytes y valida que sea
// canónico: sin ceros a la izquierda y mayor que 55 (si no, debió usarse la
// forma corta).
func readLongLength(b []byte, ll int) (uint64, error) {
	if ll > 8 {
		return 0, ErrRLPUintOverflow
	}
	if len(b) < ll {
		return 0, ErrRLPTruncated
	}
	if b[0] == 0 {
		return 0, ErrRLPNonCanonical
	}
	var n uint64
	for i := 0; i < ll; i++ {
		n = n<<8 | uint64(b[i])
	}
	if n <= 55 {
		return 0, ErrRLPNonCanonical
	}
	// Límite de cordura: nada en el protocolo mide más de 1 GiB.
	if n > 1<<30 {
		return 0, ErrRLPTruncated
	}
	return n, nil
}

// decodeChildren decodifica todos los elementos de un payload de lista.
func decodeChildren(payload []byte, depth int) ([]RLPItem, error) {
	var out []RLPItem
	for len(payload) > 0 {
		it, rest, err := decodeItem(payload, depth+1)
		if err != nil {
			return nil, err
		}
		out = append(out, it)
		payload = rest
	}
	return out, nil
}

// IsList informa si el ítem es una lista.
func (it RLPItem) IsList() bool { return it.Kind == RLPList }

// Bytes devuelve el contenido de un string, o error si es lista.
func (it RLPItem) Bytes() ([]byte, error) {
	if it.Kind != RLPString {
		return nil, ErrRLPExpectedString
	}
	return it.Data, nil
}

// BytesCopy es como Bytes pero devuelve una copia independiente del buffer.
func (it RLPItem) BytesCopy() ([]byte, error) {
	b, err := it.Bytes()
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), b...), nil
}

// Uint64 interpreta el ítem como entero sin signo canónico de hasta 64 bits.
func (it RLPItem) Uint64() (uint64, error) {
	b, err := it.Bytes()
	if err != nil {
		return 0, err
	}
	if len(b) > 8 {
		return 0, ErrRLPUintOverflow
	}
	if len(b) > 0 && b[0] == 0 {
		// Ceros a la izquierda: no canónico.
		return 0, ErrRLPNonCanonical
	}
	var u uint64
	for _, c := range b {
		u = u<<8 | uint64(c)
	}
	return u, nil
}

// Bool interpreta el ítem como booleano (sólo 0 o 1).
func (it RLPItem) Bool() (bool, error) {
	u, err := it.Uint64()
	if err != nil {
		return false, err
	}
	if u > 1 {
		return false, ErrRLPUintOverflow
	}
	return u == 1, nil
}

// Big interpreta el ítem como entero grande no negativo de hasta 256 bits.
func (it RLPItem) Big() (*big.Int, error) {
	b, err := it.Bytes()
	if err != nil {
		return nil, err
	}
	if len(b) > 32 {
		return nil, ErrRLPUintOverflow
	}
	if len(b) > 0 && b[0] == 0 {
		return nil, ErrRLPNonCanonical
	}
	return new(big.Int).SetBytes(b), nil
}

// Hash interpreta el ítem como un hash de exactamente 32 bytes.
func (it RLPItem) Hash() (Hash, error) {
	b, err := it.Bytes()
	if err != nil {
		return Hash{}, err
	}
	if len(b) != HashLength {
		return Hash{}, ErrInvalidLength
	}
	return BytesToHash(b), nil
}

// Address interpreta el ítem como una dirección de exactamente 20 bytes.
func (it RLPItem) Address() (Address, error) {
	b, err := it.Bytes()
	if err != nil {
		return Address{}, err
	}
	if len(b) != AddressLength {
		return Address{}, ErrInvalidLength
	}
	return BytesToAddress(b), nil
}

// ListN devuelve los hijos de una lista exigiendo exactamente n elementos.
func (it RLPItem) ListN(n int) ([]RLPItem, error) {
	if it.Kind != RLPList {
		return nil, ErrRLPExpectedList
	}
	if len(it.List) != n {
		return nil, fmt.Errorf("%w: se esperaban %d, hay %d", ErrRLPListCount, n, len(it.List))
	}
	return it.List, nil
}

// Items devuelve los hijos de una lista de largo arbitrario.
func (it RLPItem) Items() ([]RLPItem, error) {
	if it.Kind != RLPList {
		return nil, ErrRLPExpectedList
	}
	return it.List, nil
}

// ---------------------------------------------------------------------------
// Utilidades hexadecimales (formato "0x...")
// ---------------------------------------------------------------------------

// EncodeHex devuelve b como hexadecimal en minúsculas con prefijo "0x".
func EncodeHex(b []byte) string {
	return "0x" + hex.EncodeToString(b)
}

// DecodeHex parsea una cadena hexadecimal con prefijo "0x" obligatorio.
// Acepta un número impar de dígitos completando con un cero a la izquierda,
// lo que resulta cómodo para valores escritos a mano en el génesis.
func DecodeHex(s string) ([]byte, error) {
	if !has0xPrefix(s) {
		return nil, ErrMissingHexPrefix
	}
	s = s[2:]
	if len(s)%2 == 1 {
		s = "0" + s
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidHex, err)
	}
	return b, nil
}

// has0xPrefix informa si s empieza con "0x" o "0X".
func has0xPrefix(s string) bool {
	return len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')
}

// HexBytes es un []byte que se serializa en JSON/texto como "0x...".
type HexBytes []byte

// MarshalText implementa encoding.TextMarshaler.
func (h HexBytes) MarshalText() ([]byte, error) { return []byte(EncodeHex(h)), nil }

// UnmarshalText implementa encoding.TextUnmarshaler.
func (h *HexBytes) UnmarshalText(text []byte) error {
	b, err := DecodeHex(string(text))
	if err != nil {
		return err
	}
	*h = b
	return nil
}

// String devuelve la representación hexadecimal.
func (h HexBytes) String() string { return EncodeHex(h) }

// HexUint64 es un uint64 que se serializa como "cantidad" hexadecimal
// ("0x1a"), el formato estándar de JSON-RPC. Al parsear también acepta
// decimal sin prefijo, cómodo en archivos de configuración.
type HexUint64 uint64

// MarshalText implementa encoding.TextMarshaler.
func (h HexUint64) MarshalText() ([]byte, error) {
	return []byte("0x" + strconv.FormatUint(uint64(h), 16)), nil
}

// UnmarshalText implementa encoding.TextUnmarshaler.
func (h *HexUint64) UnmarshalText(text []byte) error {
	v, err := ParseUint64(string(text))
	if err != nil {
		return err
	}
	*h = HexUint64(v)
	return nil
}

// ParseUint64 parsea un entero en hexadecimal ("0x..") o decimal.
func ParseUint64(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if has0xPrefix(s) {
		v, err := strconv.ParseUint(s[2:], 16, 64)
		if err != nil {
			return 0, fmt.Errorf("%w: %v", ErrInvalidHex, err)
		}
		return v, nil
	}
	return strconv.ParseUint(s, 10, 64)
}

// ---------------------------------------------------------------------------
// Listas derivables
// ---------------------------------------------------------------------------

// EncodeUintKey codifica un índice como clave del trie de transacciones o
// recibos: RLP(i), igual que Ethereum.
func EncodeUintKey(i int) []byte { return EncodeUint(uint64(i)) }
