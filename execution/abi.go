package execution

// Este archivo implementa un subconjunto del ABI de Solidity suficiente
// para hablar con contratos (incluidos los contratos de sistema nativos) y
// decodificar errores:
//
//   - Tipos estáticos: uint<N>, int<N>, address, bool, bytes<N>.
//   - Tipos dinámicos: bytes, string y arrays dinámicos T[] de un tipo
//     estático (un nivel de anidamiento).
//
// La codificación sigue la especificación: cada argumento ocupa una
// "cabeza" de 32 bytes; los dinámicos guardan en la cabeza el desplazamiento
// hasta su "cola", donde va la longitud seguida de los datos rellenados a
// múltiplos de 32.

import (
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"strconv"
	"strings"

	"github.com/l1/l1/types"
)

// ErrABI agrupa los errores de codificación/decodificación.
var ErrABI = errors.New("abi")

func abiErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrABI, fmt.Sprintf(format, args...))
}

// abiType es un tipo ABI analizado.
type abiType struct {
	kind  string   // "uint", "int", "address", "bool", "fixedbytes", "bytes", "string", "slice"
	size  int      // bits para enteros, bytes para bytesN
	elem  *abiType // tipo de los elementos si kind == "slice"
	canon string   // nombre canónico (p.ej. "uint256")
}

// dynamic informa si el tipo usa cola.
func (t *abiType) dynamic() bool {
	return t.kind == "bytes" || t.kind == "string" || t.kind == "slice"
}

// parseABIType analiza un nombre de tipo.
func parseABIType(s string) (*abiType, error) {
	s = strings.TrimSpace(s)
	if strings.HasSuffix(s, "[]") {
		elem, err := parseABIType(strings.TrimSuffix(s, "[]"))
		if err != nil {
			return nil, err
		}
		if elem.dynamic() {
			return nil, abiErr("arrays de tipos dinámicos no soportados: %s", s)
		}
		return &abiType{kind: "slice", elem: elem, canon: elem.canon + "[]"}, nil
	}
	switch {
	case s == "address" || s == "bool" || s == "string" || s == "bytes":
		return &abiType{kind: s, canon: s}, nil
	case s == "uint" || s == "int":
		return &abiType{kind: s, size: 256, canon: s + "256"}, nil
	case strings.HasPrefix(s, "uint") || strings.HasPrefix(s, "int"):
		kind := "uint"
		if strings.HasPrefix(s, "int") {
			kind = "int"
		}
		n, err := strconv.Atoi(strings.TrimPrefix(s, kind))
		if err != nil || n <= 0 || n > 256 || n%8 != 0 {
			return nil, abiErr("tamaño de entero inválido: %s", s)
		}
		return &abiType{kind: kind, size: n, canon: s}, nil
	case strings.HasPrefix(s, "bytes"):
		n, err := strconv.Atoi(strings.TrimPrefix(s, "bytes"))
		if err != nil || n <= 0 || n > 32 {
			return nil, abiErr("tamaño de bytesN inválido: %s", s)
		}
		return &abiType{kind: "fixedbytes", size: n, canon: s}, nil
	}
	return nil, abiErr("tipo no soportado: %q", s)
}

// Selector devuelve los 4 primeros bytes de keccak256(firma).
func Selector(signature string) [4]byte {
	var out [4]byte
	copy(out[:], types.Keccak256([]byte(signature)))
	return out
}

// ParseSignature separa "nombre(t1,t2)" en nombre y tipos.
func ParseSignature(sig string) (string, []string, error) {
	open := strings.IndexByte(sig, '(')
	if open <= 0 || !strings.HasSuffix(sig, ")") {
		return "", nil, abiErr("firma inválida: %q", sig)
	}
	inner := sig[open+1 : len(sig)-1]
	var typs []string
	if inner != "" {
		typs = strings.Split(inner, ",")
	}
	return sig[:open], typs, nil
}

// PackCall codifica una llamada: selector || argumentos.
func PackCall(signature string, args ...any) ([]byte, error) {
	_, typs, err := ParseSignature(signature)
	if err != nil {
		return nil, err
	}
	enc, err := EncodeABI(typs, args)
	if err != nil {
		return nil, err
	}
	sel := Selector(signature)
	return append(sel[:], enc...), nil
}

// EncodeABI codifica una tupla de valores.
func EncodeABI(typNames []string, vals []any) ([]byte, error) {
	if len(typNames) != len(vals) {
		return nil, abiErr("se esperaban %d valores, hay %d", len(typNames), len(vals))
	}
	typs := make([]*abiType, len(typNames))
	for i, n := range typNames {
		t, err := parseABIType(n)
		if err != nil {
			return nil, err
		}
		typs[i] = t
	}
	return encodeTuple(typs, vals)
}

func encodeTuple(typs []*abiType, vals []any) ([]byte, error) {
	head := make([]byte, 0, 32*len(typs))
	var tail []byte
	for i, t := range typs {
		if t.dynamic() {
			enc, err := encodeDynamic(t, vals[i])
			if err != nil {
				return nil, err
			}
			head = append(head, abiUint(uint64(32*len(typs)+len(tail)))...)
			tail = append(tail, enc...)
			continue
		}
		word, err := encodeStatic(t, vals[i])
		if err != nil {
			return nil, err
		}
		head = append(head, word...)
	}
	return append(head, tail...), nil
}

// abiUint codifica un uint64 en una palabra.
func abiUint(v uint64) []byte {
	w := NewWord(v).Bytes32()
	return w[:]
}

// toBig convierte los enteros admitidos a *big.Int.
func toBig(v any) (*big.Int, error) {
	switch x := v.(type) {
	case *big.Int:
		return new(big.Int).Set(x), nil
	case uint64:
		return new(big.Int).SetUint64(x), nil
	case uint32:
		return new(big.Int).SetUint64(uint64(x)), nil
	case uint8:
		return new(big.Int).SetUint64(uint64(x)), nil
	case int:
		return big.NewInt(int64(x)), nil
	case int64:
		return big.NewInt(x), nil
	case types.Amount:
		return x.Big(), nil
	case *Word:
		return x.ToBig(), nil
	}
	return nil, abiErr("valor entero no soportado: %T", v)
}

func encodeStatic(t *abiType, v any) ([]byte, error) {
	out := make([]byte, 32)
	switch t.kind {
	case "uint", "int":
		b, err := toBig(v)
		if err != nil {
			return nil, err
		}
		if t.kind == "uint" {
			if b.Sign() < 0 || b.BitLen() > t.size {
				return nil, abiErr("%s fuera de rango: %s", t.canon, b)
			}
			return b.FillBytes(out), nil
		}
		lim := new(big.Int).Lsh(big.NewInt(1), uint(t.size-1))
		if b.Cmp(lim) >= 0 || b.Cmp(new(big.Int).Neg(lim)) < 0 {
			return nil, abiErr("%s fuera de rango: %s", t.canon, b)
		}
		w := WordFromBig(new(big.Int).And(b, new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))))
		bs := w.Bytes32()
		return bs[:], nil
	case "address":
		a, ok := v.(types.Address)
		if !ok {
			return nil, abiErr("se esperaba types.Address, hay %T", v)
		}
		copy(out[12:], a[:])
		return out, nil
	case "bool":
		b, ok := v.(bool)
		if !ok {
			return nil, abiErr("se esperaba bool, hay %T", v)
		}
		if b {
			out[31] = 1
		}
		return out, nil
	case "fixedbytes":
		var raw []byte
		switch x := v.(type) {
		case types.Hash:
			raw = x[:]
		case []byte:
			raw = x
		default:
			return nil, abiErr("se esperaban bytes para %s, hay %T", t.canon, v)
		}
		if len(raw) > t.size {
			return nil, abiErr("%s demasiado largo (%d)", t.canon, len(raw))
		}
		copy(out, raw) // alineado a la izquierda
		return out, nil
	}
	return nil, abiErr("tipo estático desconocido %s", t.canon)
}

// padRight rellena hasta múltiplo de 32.
func padRight(b []byte) []byte {
	n := (len(b) + 31) / 32 * 32
	out := make([]byte, n)
	copy(out, b)
	return out
}

func encodeDynamic(t *abiType, v any) ([]byte, error) {
	switch t.kind {
	case "bytes":
		b, ok := v.([]byte)
		if !ok {
			return nil, abiErr("se esperaba []byte, hay %T", v)
		}
		return append(abiUint(uint64(len(b))), padRight(b)...), nil
	case "string":
		s, ok := v.(string)
		if !ok {
			return nil, abiErr("se esperaba string, hay %T", v)
		}
		return append(abiUint(uint64(len(s))), padRight([]byte(s))...), nil
	case "slice":
		rv := reflect.ValueOf(v)
		if rv.Kind() != reflect.Slice {
			return nil, abiErr("se esperaba un slice, hay %T", v)
		}
		out := abiUint(uint64(rv.Len()))
		for i := 0; i < rv.Len(); i++ {
			w, err := encodeStatic(t.elem, rv.Index(i).Interface())
			if err != nil {
				return nil, err
			}
			out = append(out, w...)
		}
		return out, nil
	}
	return nil, abiErr("tipo dinámico desconocido %s", t.canon)
}

// DecodeABI decodifica una tupla. Tipos devueltos: *big.Int (enteros),
// types.Address, bool, []byte (bytesN y bytes), string y []any (arrays).
func DecodeABI(typNames []string, data []byte) ([]any, error) {
	out := make([]any, len(typNames))
	for i, n := range typNames {
		t, err := parseABIType(n)
		if err != nil {
			return nil, err
		}
		if len(data) < 32*(i+1) {
			return nil, abiErr("datos truncados en el argumento %d", i)
		}
		word := data[32*i : 32*(i+1)]
		if !t.dynamic() {
			v, err := decodeStatic(t, word)
			if err != nil {
				return nil, err
			}
			out[i] = v
			continue
		}
		off, err := abiReadLen(word, len(data))
		if err != nil {
			return nil, err
		}
		v, err := decodeDynamic(t, data, off)
		if err != nil {
			return nil, err
		}
		out[i] = v
	}
	return out, nil
}

// abiReadLen lee una palabra como entero acotado por limit.
func abiReadLen(word []byte, limit int) (int, error) {
	b := new(big.Int).SetBytes(word)
	if !b.IsUint64() || b.Uint64() > uint64(limit) {
		return 0, abiErr("desplazamiento/longitud fuera de rango")
	}
	return int(b.Uint64()), nil
}

func decodeStatic(t *abiType, w []byte) (any, error) {
	switch t.kind {
	case "uint":
		b := new(big.Int).SetBytes(w)
		if b.BitLen() > t.size {
			return nil, abiErr("%s fuera de rango", t.canon)
		}
		return b, nil
	case "int":
		var z Word
		z.SetBytes(w)
		return z.ToSignedBig(), nil
	case "address":
		for _, c := range w[:12] {
			if c != 0 {
				return nil, abiErr("dirección con bytes altos no nulos")
			}
		}
		return types.BytesToAddress(w[12:]), nil
	case "bool":
		for _, c := range w[:31] {
			if c != 0 {
				return nil, abiErr("bool inválido")
			}
		}
		if w[31] > 1 {
			return nil, abiErr("bool inválido")
		}
		return w[31] == 1, nil
	case "fixedbytes":
		return append([]byte(nil), w[:t.size]...), nil
	}
	return nil, abiErr("tipo estático desconocido %s", t.canon)
}

func decodeDynamic(t *abiType, data []byte, off int) (any, error) {
	if off+32 > len(data) {
		return nil, abiErr("cola fuera de los datos")
	}
	n, err := abiReadLen(data[off:off+32], len(data))
	if err != nil {
		return nil, err
	}
	start := off + 32
	switch t.kind {
	case "bytes", "string":
		if start+n > len(data) {
			return nil, abiErr("contenido truncado")
		}
		raw := append([]byte(nil), data[start:start+n]...)
		if t.kind == "string" {
			return string(raw), nil
		}
		return raw, nil
	case "slice":
		if start+32*n > len(data) {
			return nil, abiErr("array truncado")
		}
		out := make([]any, n)
		for i := 0; i < n; i++ {
			v, err := decodeStatic(t.elem, data[start+32*i:start+32*(i+1)])
			if err != nil {
				return nil, err
			}
			out[i] = v
		}
		return out, nil
	}
	return nil, abiErr("tipo dinámico desconocido %s", t.canon)
}

// EncodeRevertReason construye los datos de Error(string), como haría
// require(cond, "motivo") en Solidity.
func EncodeRevertReason(reason string) []byte {
	enc, _ := EncodeABI([]string{"string"}, []any{reason})
	return append(append([]byte(nil), revertSelector...), enc...)
}
