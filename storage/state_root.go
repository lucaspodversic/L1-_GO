package storage

// Cálculo de la raíz de estado y confirmación.
//
//	Finalise         → fin de cada transacción: consolida cambios, borra
//	                   cuentas destruidas/vacías, limpia el journal.
//	IntermediateRoot → aplica lo pendiente al trie y devuelve la raíz (la
//	                   que va en la cabecera del bloque).
//	Commit           → además produce y entrega los nodos nuevos a la
//	                   NodeDatabase y escribe el código nuevo en disco.

import (
	"github.com/l1/l1/types"
)

// Finalise consolida los cambios de la tx actual. Con deleteEmpty se
// eliminan las cuentas vacías tocadas (EIP-161, siempre activo en esta red).
func (s *StateDB) Finalise(deleteEmpty bool) {
	for addr := range s.journal.dirties {
		obj, ok := s.stateObjects[addr]
		if !ok {
			continue // creada y revertida dentro de la tx
		}
		if obj.selfDestructed || (deleteEmpty && obj.empty()) {
			obj.deleted = true
			s.stateObjectsDestruct[addr] = struct{}{}
		} else {
			obj.finalise()
		}
		s.stateObjectsPending[addr] = struct{}{}
		s.stateObjectsDirty[addr] = struct{}{}
	}
	s.clearJournalAndRefund()
}

// IntermediateRoot finaliza y calcula la raíz de estado actual.
func (s *StateDB) IntermediateRoot(deleteEmpty bool) types.Hash {
	s.Finalise(deleteEmpty)
	for addr := range s.stateObjectsPending {
		obj := s.stateObjects[addr]
		if obj == nil || obj.deleted {
			if err := s.trie.DeleteAccount(addr); err != nil {
				s.setError(err)
			}
			continue
		}
		if err := obj.updateRoot(); err != nil {
			s.setError(err)
			continue
		}
		if err := s.trie.UpdateAccount(addr, &obj.data); err != nil {
			s.setError(err)
		}
	}
	clear(s.stateObjectsPending)
	return s.trie.Hash()
}

// Commit calcula la raíz, escribe el código nuevo en disco y entrega los
// nodos nuevos de todos los tries a la NodeDatabase. Si flush es true los
// nodos se vuelcan además a disco (si no, quedan en memoria hasta que la
// cadena llame a NodeDatabase.Flush, p. ej. al finalizar un bloque).
func (s *StateDB) Commit(deleteEmpty, flush bool) (types.Hash, error) {
	if s.dbErr != nil {
		return types.Hash{}, s.dbErr
	}
	root := s.IntermediateRoot(deleteEmpty)
	if s.dbErr != nil {
		return types.Hash{}, s.dbErr
	}
	set := NewNodeSet()
	batch := s.db.disk.NewBatch()
	for addr := range s.stateObjectsDirty {
		obj := s.stateObjects[addr]
		if obj == nil || obj.deleted {
			delete(s.stateObjects, addr)
			continue
		}
		if obj.dirtyCode {
			if err := s.db.WriteCode(batch, obj.data.CodeHash, obj.code); err != nil {
				return types.Hash{}, err
			}
			obj.dirtyCode = false
		}
		ns, err := obj.commit()
		if err != nil {
			return types.Hash{}, err
		}
		set.Merge(ns)
	}
	_, ns := s.trie.Commit()
	set.Merge(ns)
	if err := batch.Write(); err != nil {
		return types.Hash{}, err
	}
	s.db.nodes.Update(set)
	if flush {
		if err := s.db.nodes.Flush(); err != nil {
			return types.Hash{}, err
		}
	}
	s.originalRoot = root
	clear(s.stateObjectsDirty)
	clear(s.stateObjectsDestruct)
	return root, nil
}

// NewListHasher devuelve un types.TrieHasher (trie en memoria) para
// calcular TxRoot/ReceiptRoot con types.DeriveRoot.
func NewListHasher() types.TrieHasher { return &listHasher{t: NewEmptyTrie()} }

// DeriveSha es un atajo de types.DeriveRoot con un trie en memoria.
func DeriveSha(list types.DerivableList) types.Hash {
	h, _ := types.DeriveRoot(list, NewListHasher()) // en memoria no hay errores de E/S
	return h
}
