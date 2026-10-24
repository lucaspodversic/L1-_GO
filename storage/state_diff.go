package storage

// Diferencias entre dos estados (dos raíces). Sirve para depurar
// divergencias de consenso ("¿qué cuenta difiere entre mi raíz y la del
// bloque?"), para el RPC de trazas y para sincronizar estado de forma
// incremental.
//
// El algoritmo aprovecha la estructura de Merkle: si dos subárboles tienen
// el mismo hash son idénticos y se saltan sin cargarlos. Así, el coste es
// proporcional al tamaño del cambio y no al del estado.

import (
	"bytes"

	"github.com/l1/l1/types"
)

// Walk recorre todas las hojas del trie en orden de clave, llamando a fn
// con la clave original (en un trie seguro, la clave hasheada) y el valor.
func (t *Trie) Walk(fn func(key, value []byte) error) error { return t.walk(t.root, nil, fn) }

// walk es el recorrido recursivo; path es la ruta en nibbles.
func (t *Trie) walk(n node, path []byte, fn func(key, value []byte) error) error {
	switch n := n.(type) {
	case nil:
		return nil
	case valueNode:
		return fn(hexToKeybytes(path), n)
	case *shortNode:
		return t.walk(n.Val, concat(path, n.Key), fn)
	case *fullNode:
		for i, c := range &n.Children {
			if c != nil {
				if err := t.walk(c, concat(path, []byte{byte(i)}), fn); err != nil {
					return err
				}
			}
		}
		return nil
	case hashNode:
		rn, err := t.resolveHash(n, path)
		if err != nil {
			return err
		}
		return t.walk(rn, path, fn)
	}
	return nil
}

// nodeHashOf devuelve el hash conocido de un nodo (nil si no lo tiene).
func nodeHashOf(n node) []byte {
	if h, ok := n.(hashNode); ok {
		return h
	}
	if n == nil {
		return nil
	}
	h, _ := n.cache()
	return h
}

// DiffTries llama a fn por cada clave cuyo valor difiere entre a y b
// (oldVal nil = clave añadida; newVal nil = clave borrada).
func DiffTries(a, b *Trie, fn func(key, oldVal, newVal []byte) error) error {
	a.Hash() // asegura hashes cacheados en nodos en memoria
	b.Hash()
	return diffNodes(a, b, a.root, b.root, nil, fn)
}

// diffNodes compara dos subárboles situados en la misma ruta.
func diffNodes(ta, tb *Trie, na, nb node, path []byte, fn func(k, o, n []byte) error) error {
	ha, hb := nodeHashOf(na), nodeHashOf(nb)
	if ha != nil && hb != nil && bytes.Equal(ha, hb) {
		return nil // subárboles idénticos
	}
	var err error
	if na, err = ta.resolve(na, path); err != nil {
		return err
	}
	if nb, err = tb.resolve(nb, path); err != nil {
		return err
	}
	fa, okA := na.(*fullNode)
	fb, okB := nb.(*fullNode)
	if okA && okB {
		// Dos ramas: se compara hijo a hijo.
		for i := 0; i < 17; i++ {
			if err := diffNodes(ta, tb, fa.Children[i], fb.Children[i], concat(path, []byte{byte(i)}), fn); err != nil {
				return err
			}
		}
		return nil
	}
	// Estructuras distintas: se materializan las hojas de ambos lados.
	la, err := collectLeaves(ta, na, path)
	if err != nil {
		return err
	}
	lb, err := collectLeaves(tb, nb, path)
	if err != nil {
		return err
	}
	for k, va := range la {
		vb, ok := lb[k]
		if !ok {
			if err := fn([]byte(k), va, nil); err != nil {
				return err
			}
		} else if !bytes.Equal(va, vb) {
			if err := fn([]byte(k), va, vb); err != nil {
				return err
			}
		}
	}
	for k, vb := range lb {
		if _, ok := la[k]; !ok {
			if err := fn([]byte(k), nil, vb); err != nil {
				return err
			}
		}
	}
	return nil
}

// collectLeaves devuelve las hojas de un subárbol.
func collectLeaves(t *Trie, n node, path []byte) (map[string][]byte, error) {
	out := make(map[string][]byte)
	err := t.walk(n, path, func(k, v []byte) error {
		out[string(k)] = v
		return nil
	})
	return out, err
}

// StorageChange es el cambio de un slot.
type StorageChange struct {
	// Old y New son los valores antes y después (cero = inexistente).
	Old, New types.Hash
}

// AccountDiff describe el cambio de una cuenta.
type AccountDiff struct {
	// AddrHash es keccak(dirección), la clave en el trie.
	AddrHash types.Hash
	// Address es la dirección si se conoce su preimagen.
	Address *types.Address
	// Old y New son la cuenta antes y después (nil = inexistente).
	Old, New *types.Account
	// Storage son los slots cambiados, indexados por keccak(slot).
	Storage map[types.Hash]StorageChange
}

// StateDiff es el conjunto de cuentas que difieren.
type StateDiff struct {
	// Accounts por hash de dirección.
	Accounts map[types.Hash]*AccountDiff
}

// DiffStates compara dos raíces de estado, incluido el almacenamiento.
func DiffStates(db *StateDatabase, oldRoot, newRoot types.Hash) (*StateDiff, error) {
	ta, err := db.OpenTrie(oldRoot)
	if err != nil {
		return nil, err
	}
	tb, err := db.OpenTrie(newRoot)
	if err != nil {
		return nil, err
	}
	diff := &StateDiff{Accounts: make(map[types.Hash]*AccountDiff)}
	err = DiffTries(ta.Trie(), tb.Trie(), func(k, ov, nv []byte) error {
		ad := &AccountDiff{AddrHash: types.BytesToHash(k), Storage: make(map[types.Hash]StorageChange)}
		if pre, ok := db.nodes.Preimage(ad.AddrHash); ok && len(pre) == 20 {
			a := types.BytesToAddress(pre)
			ad.Address = &a
		}
		var err error
		if ov != nil {
			if ad.Old, err = types.DecodeAccount(ov); err != nil {
				return err
			}
		}
		if nv != nil {
			if ad.New, err = types.DecodeAccount(nv); err != nil {
				return err
			}
		}
		if err := diffStorage(db, ad); err != nil {
			return err
		}
		diff.Accounts[ad.AddrHash] = ad
		return nil
	})
	return diff, err
}

// diffStorage compara los tries de almacenamiento de una cuenta.
func diffStorage(db *StateDatabase, ad *AccountDiff) error {
	oldRoot, newRoot := types.EmptyRootHash, types.EmptyRootHash
	if ad.Old != nil {
		oldRoot = ad.Old.StorageRoot
	}
	if ad.New != nil {
		newRoot = ad.New.StorageRoot
	}
	if oldRoot == newRoot {
		return nil
	}
	sa, err := db.OpenStorageTrie(ad.AddrHash, oldRoot)
	if err != nil {
		return err
	}
	sb, err := db.OpenStorageTrie(ad.AddrHash, newRoot)
	if err != nil {
		return err
	}
	return DiffTries(sa.Trie(), sb.Trie(), func(k, ov, nv []byte) error {
		ad.Storage[types.BytesToHash(k)] = StorageChange{Old: decodeStorageWord(ov), New: decodeStorageWord(nv)}
		return nil
	})
}

// decodeStorageWord decodifica un valor de slot RLP (nil → cero).
func decodeStorageWord(raw []byte) types.Hash {
	if raw == nil {
		return types.Hash{}
	}
	it, err := types.DecodeRLP(raw)
	if err != nil {
		return types.Hash{}
	}
	b, _ := it.Bytes()
	return types.BytesToHash(b)
}
