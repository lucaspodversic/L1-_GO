package storage

// Tipos de nodo del Merkle Patricia Trie y su (de)serialización RLP.
//
//   - fullNode (rama): 16 hijos, uno por nibble, más un valor en la posición
//     16 para claves que terminan justo en esta rama.
//   - shortNode: comprime un tramo de ruta. Si su clave termina en el
//     terminador es una hoja (Val es valueNode); si no, es una extensión
//     (Val es otro nodo).
//   - hashNode: referencia a un nodo aún no cargado de la base (su hash).
//   - valueNode: el valor almacenado.
//
// Regla de referencia de Ethereum: un hijo cuya codificación RLP mide menos
// de 32 bytes se incrusta directamente en el padre; si mide 32 o más se
// guarda aparte y el padre contiene su Keccak256. La raíz siempre se hashea.

import (
	"errors"
	"fmt"
	"strings"

	"github.com/l1/l1/types"
)

// node es cualquier nodo del trie.
type node interface {
	// cache devuelve el hash cacheado (nil si no se ha calculado o el nodo
	// se incrusta) y si el nodo tiene cambios sin persistir.
	cache() (hashNode, bool)
	// fstring es una representación de depuración.
	fstring(indent string) string
}

type (
	// fullNode es un nodo rama.
	fullNode struct {
		Children [17]node
		flags    nodeFlag
	}
	// shortNode es una extensión u hoja. Key está en formato HEX.
	shortNode struct {
		Key   []byte
		Val   node
		flags nodeFlag
	}
	// hashNode es el hash (32 bytes) de un nodo almacenado.
	hashNode []byte
	// valueNode es un valor de hoja.
	valueNode []byte
)

// nodeFlag guarda metadatos de caché de un nodo en memoria.
type nodeFlag struct {
	// hash es el hash del nodo si ya se calculó (nil si cambió desde entonces).
	hash hashNode
	// dirty indica que el nodo no está aún en la base de datos.
	dirty bool
}

// cache implementa node.
func (n *fullNode) cache() (hashNode, bool) { return n.flags.hash, n.flags.dirty }

// cache implementa node.
func (n *shortNode) cache() (hashNode, bool) { return n.flags.hash, n.flags.dirty }

// cache implementa node (un hashNode es su propio hash y está persistido).
func (n hashNode) cache() (hashNode, bool) { return nil, true }

// cache implementa node.
func (n valueNode) cache() (hashNode, bool) { return nil, true }

// copy devuelve una copia superficial (los hijos se comparten; son inmutables).
func (n *fullNode) copy() *fullNode { c := *n; return &c }

// copy devuelve una copia superficial.
func (n *shortNode) copy() *shortNode { c := *n; return &c }

// fstring implementa node.
func (n *fullNode) fstring(ind string) string {
	var b strings.Builder
	b.WriteString("[\n")
	for i, c := range &n.Children {
		if c != nil {
			fmt.Fprintf(&b, "%s  %x: %s\n", ind, i, c.fstring(ind+"  "))
		}
	}
	b.WriteString(ind + "]")
	return b.String()
}

// fstring implementa node.
func (n *shortNode) fstring(ind string) string {
	return fmt.Sprintf("{%x: %s}", n.Key, n.Val.fstring(ind+"  "))
}

// fstring implementa node.
func (n hashNode) fstring(string) string { return fmt.Sprintf("<%x>", []byte(n)) }

// fstring implementa node.
func (n valueNode) fstring(string) string { return fmt.Sprintf("%x", []byte(n)) }

// String implementa fmt.Stringer para depuración.
func (n *fullNode) String() string { return n.fstring("") }

// String implementa fmt.Stringer para depuración.
func (n *shortNode) String() string { return n.fstring("") }

// ---------------------------------------------------------------------
// Codificación
// ---------------------------------------------------------------------

// encodeNode serializa un nodo "colapsado" (cuyos hijos ya son hashNode,
// valueNode, nil o nodos incrustables) en RLP.
//
//	fullNode  → [ref0, ..., ref15, valor]
//	shortNode → [compact(key), ref | valor]
func encodeNode(n node) []byte {
	switch n := n.(type) {
	case *fullNode:
		items := make([][]byte, 17)
		for i := 0; i < 16; i++ {
			items[i] = encodeRef(n.Children[i])
		}
		if v, ok := n.Children[16].(valueNode); ok {
			items[16] = types.EncodeBytes(v)
		} else {
			items[16] = types.RLPEmptyString
		}
		return types.EncodeList(items...)
	case *shortNode:
		return types.EncodeList(types.EncodeBytes(hexToCompact(n.Key)), encodeRef(n.Val))
	case hashNode:
		return types.EncodeBytes(n)
	case valueNode:
		return types.EncodeBytes(n)
	case nil:
		return types.RLPEmptyString
	}
	panic(fmt.Sprintf("trie: tipo de nodo desconocido %T", n))
}

// encodeRef codifica la referencia a un hijo dentro de su padre: string
// vacío si no existe, el hash como string, el valor como string, o la lista
// RLP del hijo incrustado tal cual (nodos < 32 bytes).
func encodeRef(n node) []byte {
	switch n := n.(type) {
	case nil:
		return types.RLPEmptyString
	case hashNode, valueNode:
		return encodeNode(n)
	default:
		return encodeNode(n) // nodo incrustado: su RLP de lista va en línea
	}
}

// ---------------------------------------------------------------------
// Decodificación
// ---------------------------------------------------------------------

// errBadNode se envuelve en los errores de decodificación.
var errBadNode = errors.New("trie: nodo inválido")

// mustDecodeNode decodifica o entra en pánico (para datos ya verificados).
func mustDecodeNode(hash, buf []byte) node {
	n, err := decodeNode(hash, buf)
	if err != nil {
		panic(fmt.Sprintf("trie: nodo %x: %v", hash, err))
	}
	return n
}

// decodeNode decodifica un nodo almacenado. hash es su hash (se guarda en
// las flags para no recalcularlo); puede ser nil para nodos incrustados.
func decodeNode(hash, buf []byte) (node, error) {
	it, err := types.DecodeRLP(buf)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errBadNode, err)
	}
	return decodeNodeItem(hash, it)
}

// decodeNodeItem decodifica un nodo a partir de su ítem RLP ya parseado.
func decodeNodeItem(hash []byte, it types.RLPItem) (node, error) {
	if !it.IsList() {
		return nil, fmt.Errorf("%w: no es una lista", errBadNode)
	}
	flag := nodeFlag{hash: hash}
	switch len(it.List) {
	case 2:
		kb, err := it.List[0].Bytes()
		if err != nil {
			return nil, fmt.Errorf("%w: clave: %v", errBadNode, err)
		}
		key := compactToHex(kb)
		if hasTerm(key) {
			// Hoja: el segundo elemento es el valor.
			v, err := it.List[1].BytesCopy()
			if err != nil {
				return nil, fmt.Errorf("%w: valor: %v", errBadNode, err)
			}
			return &shortNode{Key: key, Val: valueNode(v), flags: flag}, nil
		}
		child, err := decodeRef(it.List[1])
		if err != nil {
			return nil, err
		}
		if child == nil {
			return nil, fmt.Errorf("%w: extensión sin hijo", errBadNode)
		}
		return &shortNode{Key: key, Val: child, flags: flag}, nil
	case 17:
		n := &fullNode{flags: flag}
		for i := 0; i < 16; i++ {
			c, err := decodeRef(it.List[i])
			if err != nil {
				return nil, err
			}
			n.Children[i] = c
		}
		v, err := it.List[16].BytesCopy()
		if err != nil {
			return nil, fmt.Errorf("%w: valor de rama: %v", errBadNode, err)
		}
		if len(v) > 0 {
			n.Children[16] = valueNode(v)
		}
		return n, nil
	}
	return nil, fmt.Errorf("%w: lista de %d elementos", errBadNode, len(it.List))
}

// decodeRef decodifica la referencia a un hijo.
func decodeRef(it types.RLPItem) (node, error) {
	if it.IsList() {
		// Nodo incrustado: por la regla de referencia debe medir < 32 bytes.
		if len(it.Raw) >= 32 {
			return nil, fmt.Errorf("%w: nodo incrustado de %d bytes", errBadNode, len(it.Raw))
		}
		return decodeNodeItem(nil, it)
	}
	b, err := it.Bytes()
	if err != nil {
		return nil, err
	}
	switch len(b) {
	case 0:
		return nil, nil
	case 32:
		return hashNode(append([]byte(nil), b...)), nil
	}
	return nil, fmt.Errorf("%w: referencia de %d bytes", errBadNode, len(b))
}

// ---------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------

// hashNodeTree calcula el hash de un subárbol. Devuelve:
//   - hashed: lo que el padre debe contener (hashNode, o el nodo colapsado
//     si es incrustable y !force).
//   - cached: el mismo subárbol en memoria con los hashes cacheados en sus
//     flags, para no recalcular en la próxima llamada.
func hashNodeTree(n node, force bool) (hashed, cached node) {
	if h, _ := n.cache(); h != nil {
		return h, n
	}
	switch n := n.(type) {
	case *shortNode:
		collapsed, cached := n.copy(), n.copy()
		if _, isVal := n.Val.(valueNode); !isVal {
			collapsed.Val, cached.Val = hashNodeTree(n.Val, false)
		}
		h := storeOrInline(collapsed, force)
		if hn, ok := h.(hashNode); ok {
			cached.flags.hash = hn
		}
		return h, cached
	case *fullNode:
		collapsed, cached := n.copy(), n.copy()
		for i := 0; i < 16; i++ {
			if n.Children[i] != nil {
				collapsed.Children[i], cached.Children[i] = hashNodeTree(n.Children[i], false)
			}
		}
		h := storeOrInline(collapsed, force)
		if hn, ok := h.(hashNode); ok {
			cached.flags.hash = hn
		}
		return h, cached
	default:
		// valueNode y hashNode no se transforman.
		return n, n
	}
}

// storeOrInline aplica la regla de los 32 bytes al nodo colapsado.
func storeOrInline(collapsed node, force bool) node {
	enc := encodeNode(collapsed)
	if len(enc) < 32 && !force {
		return collapsed
	}
	return hashNode(types.Keccak256(enc))
}
