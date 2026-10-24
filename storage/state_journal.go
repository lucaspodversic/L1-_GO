package storage

// Journal del StateDB: registro de cada modificación del estado durante la
// ejecución, con la información necesaria para deshacerla. Cuando una
// llamada de la VM falla (REVERT, sin gas, excepción) se deshacen sólo las
// entradas posteriores a su snapshot, en orden inverso. Es el mecanismo que
// da semántica transaccional anidada a CALL/CREATE.

import (
	"github.com/l1/l1/types"
)

// journalEntry es una modificación reversible.
type journalEntry interface {
	// revert deshace la modificación.
	revert(s *StateDB)
	// dirtied devuelve la cuenta modificada (nil si no afecta a ninguna).
	dirtied() *types.Address
}

// journal es la lista de entradas más un contador de modificaciones por
// cuenta, que permite saber qué cuentas tocar en Finalise.
type journal struct {
	entries []journalEntry
	dirties map[types.Address]int
}

// newJournal crea un journal vacío.
func newJournal() *journal { return &journal{dirties: make(map[types.Address]int)} }

// append registra una entrada.
func (j *journal) append(e journalEntry) {
	j.entries = append(j.entries, e)
	if a := e.dirtied(); a != nil {
		j.dirties[*a]++
	}
}

// revertTo deshace todas las entradas con índice ≥ snapshot.
func (j *journal) revertTo(s *StateDB, snapshot int) {
	for i := len(j.entries) - 1; i >= snapshot; i-- {
		j.entries[i].revert(s)
		if a := j.entries[i].dirtied(); a != nil {
			if j.dirties[*a]--; j.dirties[*a] == 0 {
				delete(j.dirties, *a)
			}
		}
	}
	j.entries = j.entries[:snapshot]
}

// dirty marca una cuenta como modificada sin entrada reversible (se usa
// al copiar un StateDB).
func (j *journal) dirty(a types.Address) { j.dirties[a]++ }

// length devuelve el número de entradas.
func (j *journal) length() int { return len(j.entries) }

// reset vacía el journal (al final de cada transacción).
func (j *journal) reset() {
	j.entries = j.entries[:0]
	j.dirties = make(map[types.Address]int)
}

// Tipos de entrada. Cada uno guarda el valor PREVIO.
type (
	// createObjectChange: se creó una cuenta que no existía.
	createObjectChange struct{ account types.Address }
	// resetObjectChange: se recreó una cuenta existente (prev es la anterior).
	resetObjectChange struct {
		account types.Address
		prev    *stateObject
	}
	// createContractChange: la cuenta se marcó como contrato creado en esta tx.
	createContractChange struct{ account types.Address }
	// selfDestructChange: SELFDESTRUCT.
	selfDestructChange struct {
		account     types.Address
		prev        bool
		prevBalance types.Amount
	}
	// balanceChange: cambio de saldo.
	balanceChange struct {
		account types.Address
		prev    types.Amount
	}
	// nonceChange: cambio de nonce.
	nonceChange struct {
		account types.Address
		prev    uint64
	}
	// storageChange: cambio de un slot.
	storageChange struct {
		account  types.Address
		key      types.Hash
		prev     types.Hash
		prevDirt bool // si el slot ya estaba en dirtyStorage
	}
	// codeChange: cambio de código.
	codeChange struct {
		account  types.Address
		prevCode []byte
		prevHash types.Hash
		prevDirt bool
	}
	// refundChange: cambio del contador de reembolso.
	refundChange struct{ prev uint64 }
	// addLogChange: se emitió un log en la tx txHash.
	addLogChange struct{ txHash types.Hash }
	// touchChange: la cuenta se "tocó" (relevante para borrar vacías, EIP-161).
	touchChange struct{ account types.Address }
	// accessListAddAccountChange: dirección añadida a la access list.
	accessListAddAccountChange struct{ address types.Address }
	// accessListAddSlotChange: slot añadido a la access list.
	accessListAddSlotChange struct {
		address types.Address
		slot    types.Hash
	}
	// transientStorageChange: cambio de almacenamiento transitorio (TSTORE).
	transientStorageChange struct {
		account  types.Address
		key      types.Hash
		prevalue types.Hash
	}
)

// revert implementa journalEntry.
func (ch createObjectChange) revert(s *StateDB) {
	delete(s.stateObjects, ch.account)
}

// dirtied implementa journalEntry.
func (ch createObjectChange) dirtied() *types.Address { return &ch.account }

// revert implementa journalEntry.
func (ch resetObjectChange) revert(s *StateDB) { s.stateObjects[ch.account] = ch.prev }

// dirtied implementa journalEntry.
func (ch resetObjectChange) dirtied() *types.Address { return &ch.account }

// revert implementa journalEntry.
func (ch createContractChange) revert(s *StateDB) {
	if obj := s.stateObjects[ch.account]; obj != nil {
		obj.newContract = false
	}
}

// dirtied implementa journalEntry.
func (ch createContractChange) dirtied() *types.Address { return nil }

// revert implementa journalEntry.
func (ch selfDestructChange) revert(s *StateDB) {
	if obj := s.getStateObject(ch.account); obj != nil {
		obj.selfDestructed = ch.prev
		obj.setBalance(ch.prevBalance)
	}
}

// dirtied implementa journalEntry.
func (ch selfDestructChange) dirtied() *types.Address { return &ch.account }

// revert implementa journalEntry.
func (ch balanceChange) revert(s *StateDB) { s.getStateObject(ch.account).setBalance(ch.prev) }

// dirtied implementa journalEntry.
func (ch balanceChange) dirtied() *types.Address { return &ch.account }

// revert implementa journalEntry.
func (ch nonceChange) revert(s *StateDB) { s.getStateObject(ch.account).setNonce(ch.prev) }

// dirtied implementa journalEntry.
func (ch nonceChange) dirtied() *types.Address { return &ch.account }

// revert implementa journalEntry.
func (ch storageChange) revert(s *StateDB) {
	obj := s.getStateObject(ch.account)
	if ch.prevDirt {
		obj.dirtyStorage[ch.key] = ch.prev
	} else {
		delete(obj.dirtyStorage, ch.key)
	}
}

// dirtied implementa journalEntry.
func (ch storageChange) dirtied() *types.Address { return &ch.account }

// revert implementa journalEntry.
func (ch codeChange) revert(s *StateDB) {
	obj := s.getStateObject(ch.account)
	obj.code, obj.data.CodeHash, obj.dirtyCode = ch.prevCode, ch.prevHash, ch.prevDirt
}

// dirtied implementa journalEntry.
func (ch codeChange) dirtied() *types.Address { return &ch.account }

// revert implementa journalEntry.
func (ch refundChange) revert(s *StateDB) { s.refund = ch.prev }

// dirtied implementa journalEntry.
func (ch refundChange) dirtied() *types.Address { return nil }

// revert implementa journalEntry.
func (ch addLogChange) revert(s *StateDB) {
	logs := s.logs[ch.txHash]
	if len(logs) == 1 {
		delete(s.logs, ch.txHash)
	} else {
		s.logs[ch.txHash] = logs[:len(logs)-1]
	}
	s.logSize--
}

// dirtied implementa journalEntry.
func (ch addLogChange) dirtied() *types.Address { return nil }

// revert implementa journalEntry (tocar no cambia valores).
func (ch touchChange) revert(s *StateDB) {}

// dirtied implementa journalEntry: lo importante es marcar la cuenta.
func (ch touchChange) dirtied() *types.Address { return &ch.account }

// revert implementa journalEntry. Las access lists sólo crecen dentro de
// una tx, así que deshacer es simplemente borrar la última inserción.
func (ch accessListAddAccountChange) revert(s *StateDB) { s.accessList.DeleteAddress(ch.address) }

// dirtied implementa journalEntry.
func (ch accessListAddAccountChange) dirtied() *types.Address { return nil }

// revert implementa journalEntry.
func (ch accessListAddSlotChange) revert(s *StateDB) { s.accessList.DeleteSlot(ch.address, ch.slot) }

// dirtied implementa journalEntry.
func (ch accessListAddSlotChange) dirtied() *types.Address { return nil }

// revert implementa journalEntry.
func (ch transientStorageChange) revert(s *StateDB) {
	s.setTransientState(ch.account, ch.key, ch.prevalue)
}

// dirtied implementa journalEntry.
func (ch transientStorageChange) dirtied() *types.Address { return nil }
