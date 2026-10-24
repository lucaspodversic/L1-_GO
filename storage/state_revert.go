package storage

// Snapshots anidados del StateDB. Cada CALL/CREATE de la VM toma un
// snapshot antes de ejecutar y, si la llamada falla, revierte a él. Un
// snapshot es simplemente un identificador asociado a la longitud del
// journal en ese momento; revertir deshace las entradas posteriores.

import (
	"fmt"
	"sort"
)

// revision asocia un id de snapshot con una posición del journal.
type revision struct {
	id           int
	journalIndex int
}

// Snapshot devuelve un identificador del estado actual.
func (s *StateDB) Snapshot() int {
	id := s.nextRevisionID
	s.nextRevisionID++
	s.validRevisions = append(s.validRevisions, revision{id: id, journalIndex: s.journal.length()})
	return id
}

// RevertToSnapshot deshace todos los cambios posteriores al snapshot. Los
// snapshots más recientes que él quedan invalidados. Revertir a un id
// inexistente es un error de programación (pánico).
func (s *StateDB) RevertToSnapshot(revid int) {
	// Los ids son crecientes: búsqueda binaria.
	idx := sort.Search(len(s.validRevisions), func(i int) bool { return s.validRevisions[i].id >= revid })
	if idx == len(s.validRevisions) || s.validRevisions[idx].id != revid {
		panic(fmt.Errorf("state: snapshot %d no válido", revid))
	}
	snapshot := s.validRevisions[idx].journalIndex
	s.journal.revertTo(s, snapshot)
	s.validRevisions = s.validRevisions[:idx]
}

// clearJournalAndRefund se llama al final de cada tx: los cambios pasan a
// ser definitivos dentro del bloque y el reembolso se reinicia.
func (s *StateDB) clearJournalAndRefund() {
	if s.journal.length() > 0 || len(s.journal.dirties) > 0 {
		s.journal.reset()
	}
	s.validRevisions = s.validRevisions[:0]
	s.refund = 0
}
