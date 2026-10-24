package storage

// Pruebas de Merkle del trie (formato de eth_getProof / EIP-1186).
//
// Una prueba para una clave es la lista de nodos (RLP) que se recorren desde
// la raíz hasta donde termina la búsqueda. Basta para que un cliente ligero
// que sólo conoce la raíz verifique tanto la PRESENCIA de un valor como su
// AUSENCIA (la ruta termina en un hueco o diverge de un shortNode).
// Los nodos incrustados no aparecen por separado: viajan dentro de su padre.

import (
	"errors"
	"fmt"

	"github.com/l1/l1/types"
)

// ErrProofInvalid indica que la prueba no es coherente con la raíz.
var ErrProofInvalid = errors.New("trie: prueba inválida")

// Prove construye la prueba para key. Funciona tanto si la clave existe
// como si no (prueba de ausencia).
func (t *Trie) Prove(key []byte) ([][]byte, error) {
	hex := keybytesToHex(key)
	var nodes []node
	tn := t.root
	prefix := []byte{}
	// Recorrido: se acumulan los nodos visitados (resolviendo hashNode).
	for len(hex) > 0 && tn != nil {
		switch n := tn.(type) {
		case *shortNode:
			nodes = append(nodes, n)
			if len(hex) < len(n.Key) || !keysEqualPrefix(n.Key, hex) {
				tn = nil // diverge: prueba de ausencia
			} else {
				tn = n.Val
				prefix = concat(prefix, hex[:len(n.Key)])
				hex = hex[len(n.Key):]
			}
		case *fullNode:
			nodes = append(nodes, n)
			tn = n.Children[hex[0]]
			prefix = concat(prefix, hex[:1])
			hex = hex[1:]
		case hashNode:
			rn, err := t.resolveHash(n, prefix)
			if err != nil {
				return nil, err
			}
			tn = rn
		case valueNode:
			tn = nil
		default:
			return nil, fmt.Errorf("trie: nodo inesperado %T", tn)
		}
	}
	// Se codifica cada nodo visitado; sólo se incluyen los que se almacenan
	// aparte (≥ 32 bytes) y siempre la raíz.
	proof := make([][]byte, 0, len(nodes))
	for i, n := range nodes {
		collapsed := collapseForProof(n)
		enc := encodeNode(collapsed)
		if len(enc) >= 32 || i == 0 {
			proof = append(proof, enc)
		}
	}
	return proof, nil
}

// keysEqualPrefix informa si key empieza por p.
func keysEqualPrefix(p, key []byte) bool {
	return len(key) >= len(p) && prefixLen(p, key) == len(p)
}

// collapseForProof devuelve la forma colapsada de un nodo (hijos ya
// sustituidos por su hash o incrustados) para codificarlo.
func collapseForProof(n node) node {
	switch n := n.(type) {
	case *shortNode:
		c := n.copy()
		if _, isVal := n.Val.(valueNode); !isVal {
			c.Val, _ = hashNodeTree(n.Val, false)
		}
		return c
	case *fullNode:
		c := n.copy()
		for i := 0; i < 16; i++ {
			if n.Children[i] != nil {
				c.Children[i], _ = hashNodeTree(n.Children[i], false)
			}
		}
		return c
	}
	return n
}

// ProofToMap indexa una prueba por el hash de cada nodo.
func ProofToMap(proof [][]byte) map[types.Hash][]byte {
	m := make(map[types.Hash][]byte, len(proof))
	for _, p := range proof {
		m[types.Keccak256Hash(p)] = p
	}
	return m
}

// VerifyProof comprueba la prueba contra root. Devuelve el valor (nil si
// la prueba demuestra la ausencia de la clave) o ErrProofInvalid si la
// prueba está incompleta o no corresponde a la raíz.
func VerifyProof(root types.Hash, key []byte, proof [][]byte) ([]byte, error) {
	if root == types.EmptyRootHash && len(proof) == 0 {
		return nil, nil // trie vacío: ninguna clave existe
	}
	db := ProofToMap(proof)
	hex := keybytesToHex(key)
	want := root
	for {
		buf, ok := db[want]
		if !ok {
			return nil, fmt.Errorf("%w: falta el nodo %x", ErrProofInvalid, want[:])
		}
		n, err := decodeNode(want[:], buf)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrProofInvalid, err)
		}
		rest, child := walkProofNode(n, hex)
		switch c := child.(type) {
		case nil:
			return nil, nil // ausencia demostrada
		case hashNode:
			hex = rest
			want = types.BytesToHash(c)
		case valueNode:
			return append([]byte(nil), c...), nil
		default:
			return nil, fmt.Errorf("%w: nodo inesperado", ErrProofInvalid)
		}
	}
}

// walkProofNode baja por un nodo y sus hijos incrustados hasta llegar a una
// referencia externa (hashNode), un valor o un hueco. Devuelve la clave
// restante y lo encontrado.
func walkProofNode(tn node, key []byte) ([]byte, node) {
	for {
		switch n := tn.(type) {
		case *shortNode:
			if !keysEqualPrefix(n.Key, key) {
				return nil, nil
			}
			tn = n.Val
			key = key[len(n.Key):]
		case *fullNode:
			if len(key) == 0 {
				return nil, nil
			}
			tn = n.Children[key[0]]
			key = key[1:]
		case hashNode:
			return key, n
		case valueNode:
			if len(key) != 0 {
				return nil, nil
			}
			return nil, n
		case nil:
			return key, nil
		default:
			return nil, nil
		}
	}
}
