package storage

// Núcleo del Merkle Patricia Trie: estructura Trie, lectura, inserción,
// cálculo de raíz y commit.
//
// Los nodos en memoria son inmutables una vez compartidos: cada
// modificación copia la ruta desde la raíz hasta el punto cambiado
// (copy-on-write), de modo que Copy() es O(1) y un trie copiado puede
// seguir usándose de forma independiente (lo aprovecha StateDB.Copy).
// Un Trie NO es seguro para uso concurrente.

import (
	"bytes"

	"github.com/l1/l1/types"
)

// Trie es un Merkle Patricia Trie hexario compatible con Ethereum.
type Trie struct {
	root node
	db   NodeReader // puede ser nil para tries puramente en memoria
	// unhashed cuenta modificaciones desde el último Hash (informativo).
	unhashed int
}

// NewTrie abre el trie con la raíz dada. Con raíz cero o EmptyRootHash
// crea uno vacío. Si la raíz no está en db devuelve *MissingNodeError.
func NewTrie(root types.Hash, db NodeReader) (*Trie, error) {
	t := &Trie{db: db}
	if root != (types.Hash{}) && root != types.EmptyRootHash {
		if db == nil {
			return nil, &MissingNodeError{NodeHash: root}
		}
		rn, err := t.resolveHash(hashNode(root[:]), nil)
		if err != nil {
			return nil, err
		}
		t.root = rn
	}
	return t, nil
}

// NewEmptyTrie crea un trie vacío en memoria.
func NewEmptyTrie() *Trie { return &Trie{} }

// Copy devuelve una copia independiente (O(1) gracias a copy-on-write).
func (t *Trie) Copy() *Trie { c := *t; return &c }

// newFlag crea las flags de un nodo recién modificado.
func (t *Trie) newFlag() nodeFlag { return nodeFlag{dirty: true} }

// resolveHash carga y decodifica un nodo por su hash.
func (t *Trie) resolveHash(n hashNode, prefix []byte) (node, error) {
	hash := types.BytesToHash(n)
	if t.db == nil {
		return nil, &MissingNodeError{NodeHash: hash, Path: append([]byte(nil), prefix...)}
	}
	blob, err := t.db.Node(hash)
	if err != nil {
		if me, ok := err.(*MissingNodeError); ok {
			me.Path = append([]byte(nil), prefix...)
		}
		return nil, err
	}
	return decodeNode(n, blob)
}

// resolve carga n si es un hashNode; en otro caso lo devuelve tal cual.
func (t *Trie) resolve(n node, prefix []byte) (node, error) {
	if h, ok := n.(hashNode); ok {
		return t.resolveHash(h, prefix)
	}
	return n, nil
}

// Get devuelve el valor asociado a key (nil si no existe).
func (t *Trie) Get(key []byte) ([]byte, error) {
	value, newroot, didResolve, err := t.get(t.root, keybytesToHex(key), 0)
	if err == nil && didResolve {
		t.root = newroot // conserva en memoria los nodos cargados
	}
	return value, err
}

// get busca recursivamente; devuelve además el subárbol con los nodos que
// hubo que cargar sustituidos, para cachearlos.
func (t *Trie) get(orig node, key []byte, pos int) (value []byte, newnode node, didResolve bool, err error) {
	switch n := orig.(type) {
	case nil:
		return nil, nil, false, nil
	case valueNode:
		return n, n, false, nil
	case *shortNode:
		if len(key)-pos < len(n.Key) || !bytes.Equal(n.Key, key[pos:pos+len(n.Key)]) {
			return nil, n, false, nil // la ruta diverge: no existe
		}
		value, newnode, didResolve, err = t.get(n.Val, key, pos+len(n.Key))
		if err == nil && didResolve {
			n = n.copy()
			n.Val = newnode
		}
		return value, n, didResolve, err
	case *fullNode:
		value, newnode, didResolve, err = t.get(n.Children[key[pos]], key, pos+1)
		if err == nil && didResolve {
			n = n.copy()
			n.Children[key[pos]] = newnode
		}
		return value, n, didResolve, err
	case hashNode:
		child, err := t.resolveHash(n, key[:pos])
		if err != nil {
			return nil, n, true, err
		}
		value, newnode, _, err := t.get(child, key, pos)
		return value, newnode, true, err
	}
	panic("trie: tipo de nodo inválido")
}

// Update asocia value a key. Un valor vacío equivale a borrar la clave
// (en Ethereum no existen valores vacíos en el trie).
func (t *Trie) Update(key, value []byte) error {
	t.unhashed++
	k := keybytesToHex(key)
	if len(value) != 0 {
		_, n, err := t.insert(t.root, nil, k, valueNode(copyBytes(value)))
		if err != nil {
			return err
		}
		t.root = n
		return nil
	}
	_, n, err := t.delete(t.root, nil, k)
	if err != nil {
		return err
	}
	t.root = n
	return nil
}

// MustUpdate es Update que entra en pánico ante error (tries en memoria).
func (t *Trie) MustUpdate(key, value []byte) {
	if err := t.Update(key, value); err != nil {
		panic(err)
	}
}

// insert inserta value en el subárbol n. prefix es la ruta ya recorrida
// (para mensajes de error) y key el resto. Devuelve si hubo cambios y el
// nuevo subárbol.
func (t *Trie) insert(n node, prefix, key []byte, value node) (bool, node, error) {
	if len(key) == 0 {
		// Fin de la ruta: aquí va el valor.
		if v, ok := n.(valueNode); ok {
			return !bytes.Equal(v, value.(valueNode)), value, nil
		}
		return true, value, nil
	}
	switch n := n.(type) {
	case *shortNode:
		matchlen := prefixLen(key, n.Key)
		// Si la clave del nodo es prefijo completo de la nuestra, se sigue
		// bajando por su hijo.
		if matchlen == len(n.Key) {
			dirty, nn, err := t.insert(n.Val, concat(prefix, key[:matchlen]), key[matchlen:], value)
			if !dirty || err != nil {
				return false, n, err
			}
			return true, &shortNode{Key: n.Key, Val: nn, flags: t.newFlag()}, nil
		}
		// Las rutas divergen en matchlen: se crea una rama con dos hijos,
		// el resto del nodo existente y el nuevo valor.
		branch := &fullNode{flags: t.newFlag()}
		var err error
		_, branch.Children[n.Key[matchlen]], err = t.insert(nil, concat(prefix, n.Key[:matchlen+1]), n.Key[matchlen+1:], n.Val)
		if err != nil {
			return false, nil, err
		}
		_, branch.Children[key[matchlen]], err = t.insert(nil, concat(prefix, key[:matchlen+1]), key[matchlen+1:], value)
		if err != nil {
			return false, nil, err
		}
		if matchlen == 0 {
			return true, branch, nil
		}
		// El prefijo común queda en una extensión que apunta a la rama.
		return true, &shortNode{Key: key[:matchlen], Val: branch, flags: t.newFlag()}, nil

	case *fullNode:
		dirty, nn, err := t.insert(n.Children[key[0]], concat(prefix, key[:1]), key[1:], value)
		if !dirty || err != nil {
			return false, n, err
		}
		n = n.copy()
		n.flags = t.newFlag()
		n.Children[key[0]] = nn
		return true, n, nil

	case nil:
		// Subárbol vacío: una hoja (o extensión) con el resto de la clave.
		return true, &shortNode{Key: key, Val: value, flags: t.newFlag()}, nil

	case hashNode:
		// Se carga el nodo y se inserta en él. Si no hay cambios se devuelve
		// el nodo cargado para cachearlo igualmente.
		rn, err := t.resolveHash(n, prefix)
		if err != nil {
			return false, nil, err
		}
		dirty, nn, err := t.insert(rn, prefix, key, value)
		if !dirty || err != nil {
			return false, rn, err
		}
		return true, nn, nil
	}
	panic("trie: tipo de nodo inválido")
}

// Hash devuelve la raíz del trie (EmptyRootHash si está vacío) sin escribir
// nada. Cachea los hashes calculados en los nodos.
func (t *Trie) Hash() types.Hash {
	if t.root == nil {
		return types.EmptyRootHash
	}
	hashed, cached := hashNodeTree(t.root, true)
	t.root = cached
	t.unhashed = 0
	return types.BytesToHash(hashed.(hashNode))
}

// Commit calcula la raíz y devuelve todos los nodos nuevos (sucios) que
// deben persistirse. Tras el commit el trie sigue usable: sus nodos quedan
// marcados como limpios. El llamador debe entregar el NodeSet a una
// NodeDatabase (Update) antes de abrir otro trie sobre esa raíz.
func (t *Trie) Commit() (types.Hash, *NodeSet) {
	set := NewNodeSet()
	root := t.Hash()
	if t.root == nil {
		return root, set
	}
	if _, dirty := t.root.cache(); !dirty {
		return root, set // nada que persistir
	}
	_, t.root = commitNode(t.root, set)
	return root, set
}

// commitNode recorre los nodos sucios. Devuelve lo que el padre debe
// referenciar (hashNode o nodo incrustado colapsado) y el nodo limpio que
// queda en memoria. Precondición: Hash() ya se calculó (flags.hash
// presente en todo nodo que se almacena aparte).
func commitNode(n node, set *NodeSet) (ref node, clean node) {
	hash, dirty := n.cache()
	if hash != nil && !dirty {
		return hash, n
	}
	switch n := n.(type) {
	case *shortNode:
		collapsed, cleaned := n.copy(), n.copy()
		cleaned.flags.dirty = false
		if _, isVal := n.Val.(valueNode); !isVal {
			collapsed.Val, cleaned.Val = commitNode(n.Val, set)
		}
		return storeCommitted(collapsed, cleaned, hash, set)
	case *fullNode:
		collapsed, cleaned := n.copy(), n.copy()
		cleaned.flags.dirty = false
		for i := 0; i < 16; i++ {
			if n.Children[i] != nil {
				collapsed.Children[i], cleaned.Children[i] = commitNode(n.Children[i], set)
			}
		}
		return storeCommitted(collapsed, cleaned, hash, set)
	default:
		return n, n // hashNode / valueNode
	}
}

// storeCommitted añade el nodo al set si se almacena aparte (tiene hash) o
// lo devuelve colapsado para incrustarlo en el padre.
func storeCommitted(collapsed, cleaned node, hash hashNode, set *NodeSet) (node, node) {
	if hash == nil {
		return collapsed, cleaned
	}
	set.Nodes[types.BytesToHash(hash)] = encodeNode(collapsed)
	return hash, cleaned
}

// listHasher implementa types.TrieHasher con un trie en memoria. Lo usan
// DeriveRoot (TxRoot, ReceiptRoot) y la validación de bloques.
type listHasher struct{ t *Trie }

// Reset implementa types.TrieHasher.
func (h *listHasher) Reset() { h.t = NewEmptyTrie() }

// Update implementa types.TrieHasher.
func (h *listHasher) Update(k, v []byte) error { return h.t.Update(k, v) }

// Hash implementa types.TrieHasher.
func (h *listHasher) Hash() types.Hash { return h.t.Hash() }
