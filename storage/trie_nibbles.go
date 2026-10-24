package storage

// Conversión de claves del Merkle Patricia Trie entre tres representaciones
// (idénticas a las de Ethereum, para que las raíces sean compatibles):
//
//   - KEYBYTES: la clave original, p. ej. 0x64 0x6f ("do").
//   - HEX: un nibble (4 bits) por byte, con un terminador 16 opcional al
//     final que indica "esta ruta termina en un valor". "do" → 6 4 6 f 16.
//     Es la forma usada en memoria al recorrer el árbol.
//   - COMPACT (hex-prefix, Yellow Paper apéndice C): la forma serializada en
//     los nodos. El primer nibble codifica flags: bit 1 = tiene terminador
//     (hoja), bit 0 = longitud impar. Si la longitud es par se añade un
//     nibble de relleno 0 para alinear a bytes.

// terminator es el nibble que marca el fin de una clave de hoja.
const terminator = 16

// keybytesToHex expande cada byte en dos nibbles y añade el terminador.
func keybytesToHex(str []byte) []byte {
	l := len(str)*2 + 1
	nibbles := make([]byte, l)
	for i, b := range str {
		nibbles[i*2] = b / 16
		nibbles[i*2+1] = b % 16
	}
	nibbles[l-1] = terminator
	return nibbles
}

// hexToKeybytes es la inversa de keybytesToHex. La entrada debe tener un
// número par de nibbles (ignorando el terminador).
func hexToKeybytes(hex []byte) []byte {
	if hasTerm(hex) {
		hex = hex[:len(hex)-1]
	}
	if len(hex)&1 != 0 {
		panic("trie: clave hex de longitud impar")
	}
	key := make([]byte, len(hex)/2)
	decodeNibbles(hex, key)
	return key
}

// decodeNibbles empaqueta pares de nibbles en bytes.
func decodeNibbles(nibbles []byte, bytes []byte) {
	for bi, ni := 0, 0; ni < len(nibbles); bi, ni = bi+1, ni+2 {
		bytes[bi] = nibbles[ni]<<4 | nibbles[ni+1]
	}
}

// hexToCompact codifica una ruta hex en formato hex-prefix.
func hexToCompact(hex []byte) []byte {
	var flag byte
	if hasTerm(hex) {
		flag = 1
		hex = hex[:len(hex)-1]
	}
	buf := make([]byte, len(hex)/2+1)
	buf[0] = flag << 5 // flags en el nibble alto del primer byte
	if len(hex)&1 == 1 {
		buf[0] |= 1 << 4 // longitud impar
		buf[0] |= hex[0] // el primer nibble ocupa el hueco del relleno
		hex = hex[1:]
	}
	decodeNibbles(hex, buf[1:])
	return buf
}

// compactToHex decodifica una ruta hex-prefix a hex (con terminador si
// era una hoja).
func compactToHex(compact []byte) []byte {
	if len(compact) == 0 {
		return compact
	}
	base := keybytesToHex(compact)
	// keybytesToHex añadió un terminador; sólo se conserva si el flag de
	// hoja (bit 1 del primer nibble) está activo.
	if base[0] < 2 {
		base = base[:len(base)-1]
	}
	// Se saltan el nibble de flags y, si la longitud era par, el de relleno.
	chop := 2 - base[0]&1
	return base[chop:]
}

// prefixLen devuelve la longitud del prefijo común de a y b.
func prefixLen(a, b []byte) int {
	i, n := 0, min(len(a), len(b))
	for ; i < n; i++ {
		if a[i] != b[i] {
			break
		}
	}
	return i
}

// hasTerm informa si la ruta hex termina en el terminador.
func hasTerm(s []byte) bool { return len(s) > 0 && s[len(s)-1] == terminator }
