package storage

// Poda del estado por marcado y barrido (mark-and-sweep).
//
// Cada bloque crea nodos nuevos y deja huérfanos los que sustituye; sin
// poda la base crece sin límite. Como HotStuff da finalidad determinista,
// los estados anteriores al último bloque finalizado (menos un margen
// para consultas RPC históricas) nunca se volverán a necesitar.
//
//	1. Marcar: desde cada raíz a conservar se recorren todos los nodos
//	   alcanzables del trie de cuentas, de cada trie de almacenamiento y los
//	   hashes de código referenciados.
//	2. Barrer: se borran del disco los nodos ("t") y códigos ("c") no
//	   marcados.
//
// La operación debe ejecutarse sin escrituras de estado concurrentes (la
// cadena la lanza en pausa entre bloques o en el arranque offline).

import (
	"log/slog"
	"time"

	"github.com/l1/l1/types"
)

// PruneStats resume una poda.
type PruneStats struct {
	// Marked es el número de nodos alcanzables conservados.
	Marked int
	// DeletedNodes son los nodos borrados.
	DeletedNodes int
	// DeletedCode son los códigos borrados.
	DeletedCode int
	// Elapsed es la duración total.
	Elapsed time.Duration
}

// pruner mantiene el estado del marcado.
type pruner struct {
	nodes  *NodeDatabase
	marked map[types.Hash]struct{}
	codes  map[types.Hash]struct{}
}

// Prune conserva sólo los estados con las raíces dadas y borra el resto.
func Prune(nodes *NodeDatabase, retain []types.Hash) (PruneStats, error) {
	start := time.Now()
	var st PruneStats
	// Todo lo pendiente debe estar en disco antes de barrer.
	if err := nodes.Flush(); err != nil {
		return st, err
	}
	p := &pruner{nodes: nodes, marked: make(map[types.Hash]struct{}), codes: make(map[types.Hash]struct{})}
	for _, root := range retain {
		if root == types.EmptyRootHash || root.IsZero() {
			continue
		}
		if err := p.markTrie(root, p.onAccount); err != nil {
			return st, err
		}
	}
	st.Marked = len(p.marked)
	disk := nodes.Disk()
	// Barrido de nodos.
	w := NewBatchWriter(disk, 0)
	it := disk.NewIterator(trieNodePrefix, nil)
	for it.Next() {
		k := it.Key()
		if len(k) != 1+32 {
			continue
		}
		if _, ok := p.marked[types.BytesToHash(k[1:])]; !ok {
			if err := w.Delete(copyBytes(k)); err != nil {
				it.Release()
				return st, err
			}
			st.DeletedNodes++
		}
	}
	err := it.Error()
	it.Release()
	if err != nil {
		return st, err
	}
	// Barrido de códigos.
	it = disk.NewIterator(codePrefix, nil)
	for it.Next() {
		k := it.Key()
		if len(k) != 1+32 {
			continue
		}
		if _, ok := p.codes[types.BytesToHash(k[1:])]; !ok {
			if err := w.Delete(copyBytes(k)); err != nil {
				it.Release()
				return st, err
			}
			st.DeletedCode++
		}
	}
	err = it.Error()
	it.Release()
	if err != nil {
		return st, err
	}
	if err := w.Flush(); err != nil {
		return st, err
	}
	nodes.ResetCache() // la caché podría contener nodos borrados
	st.Elapsed = time.Since(start)
	slog.Info("poda de estado completada", "conservados", st.Marked, "nodos", st.DeletedNodes,
		"códigos", st.DeletedCode, "duración", st.Elapsed)
	return st, nil
}

// markTrie marca todos los nodos de un trie; onLeaf se llama por cada valor.
func (p *pruner) markTrie(root types.Hash, onLeaf func([]byte) error) error {
	if _, ok := p.marked[root]; ok {
		return nil // subárbol compartido ya recorrido
	}
	raw, err := p.nodes.Node(root)
	if err != nil {
		return err
	}
	p.marked[root] = struct{}{}
	n, err := decodeNode(root[:], raw)
	if err != nil {
		return err
	}
	return p.markNode(n, onLeaf)
}

// markNode recorre un nodo decodificado (y sus hijos incrustados).
func (p *pruner) markNode(n node, onLeaf func([]byte) error) error {
	switch n := n.(type) {
	case *shortNode:
		return p.markNode(n.Val, onLeaf)
	case *fullNode:
		for _, c := range &n.Children {
			if c != nil {
				if err := p.markNode(c, onLeaf); err != nil {
					return err
				}
			}
		}
	case hashNode:
		return p.markTrie(types.BytesToHash(n), onLeaf)
	case valueNode:
		if onLeaf != nil {
			return onLeaf(n)
		}
	}
	return nil
}

// onAccount marca el almacenamiento y el código de una cuenta.
func (p *pruner) onAccount(raw []byte) error {
	acc, err := types.DecodeAccount(raw)
	if err != nil {
		return err
	}
	if acc.StorageRoot != types.EmptyRootHash {
		if err := p.markTrie(acc.StorageRoot, nil); err != nil {
			return err
		}
	}
	if acc.CodeHash != types.EmptyCodeHash {
		p.codes[acc.CodeHash] = struct{}{}
	}
	return nil
}
