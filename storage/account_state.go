package storage

// stateObject: representación en memoria de una cuenta durante la
// ejecución de un bloque.
//
// El almacenamiento de un contrato se maneja en tres niveles:
//
//	dirtyStorage   → escrito en la transacción en curso (reversible).
//	pendingStorage → escrito en transacciones anteriores del bloque; ya no
//	                 es reversible pero aún no está en el trie.
//	originStorage  → valores leídos del trie (o ya escritos en él):
//	                 caché del estado confirmado.
//
// Esta separación permite a la VM obtener el "valor original" de un slot
// al inicio de la tx (GetCommittedState, necesario para el coste de SSTORE
// de EIP-2200/3529) y aplazar la escritura en el trie hasta IntermediateRoot.

import (
	"github.com/l1/l1/types"
)

// Storage es un mapa slot → valor.
type Storage map[types.Hash]types.Hash

// Copy devuelve una copia.
func (s Storage) Copy() Storage {
	c := make(Storage, len(s))
	for k, v := range s {
		c[k] = v
	}
	return c
}

// stateObject es una cuenta en memoria.
type stateObject struct {
	db       *StateDB
	address  types.Address
	addrHash types.Hash
	// data es el estado de consenso actual de la cuenta.
	data types.Account
	// trie es el trie de almacenamiento (se abre bajo demanda).
	trie *SecureTrie
	// code es el bytecode (cargado bajo demanda).
	code []byte

	originStorage  Storage
	pendingStorage Storage
	dirtyStorage   Storage

	// dirtyCode indica código nuevo pendiente de escribir en disco.
	dirtyCode bool
	// selfDestructed indica SELFDESTRUCT ejecutado en esta tx.
	selfDestructed bool
	// newContract indica que la cuenta se creó como contrato en esta tx
	// (EIP-6780: sólo entonces SELFDESTRUCT borra la cuenta).
	newContract bool
	// deleted indica que la cuenta se eliminó en Finalise (vacía o destruida).
	deleted bool
}

// newObject crea el objeto; acc nil significa cuenta nueva vacía.
func newObject(db *StateDB, addr types.Address, acc *types.Account) *stateObject {
	data := types.NewEmptyAccount()
	if acc != nil {
		data = *acc.Copy()
	}
	if data.StorageRoot.IsZero() {
		data.StorageRoot = types.EmptyRootHash
	}
	if data.CodeHash.IsZero() {
		data.CodeHash = types.EmptyCodeHash
	}
	return &stateObject{
		db: db, address: addr, addrHash: types.Keccak256Hash(addr[:]), data: data,
		originStorage: make(Storage), pendingStorage: make(Storage), dirtyStorage: make(Storage),
	}
}

// empty aplica la definición de cuenta vacía de EIP-161.
func (o *stateObject) empty() bool { return o.data.IsEmpty() }

// Address devuelve la dirección.
func (o *stateObject) Address() types.Address { return o.address }

// touch marca la cuenta como tocada.
func (o *stateObject) touch() { o.db.journal.append(touchChange{account: o.address}) }

// getTrie abre (una vez) el trie de almacenamiento.
func (o *stateObject) getTrie() (*SecureTrie, error) {
	if o.trie == nil {
		tr, err := o.db.db.OpenStorageTrie(o.addrHash, o.data.StorageRoot)
		if err != nil {
			return nil, err
		}
		o.trie = tr
	}
	return o.trie, nil
}

// GetState devuelve el valor actual de un slot.
func (o *stateObject) GetState(key types.Hash) types.Hash {
	if v, ok := o.dirtyStorage[key]; ok {
		return v
	}
	return o.GetCommittedState(key)
}

// GetCommittedState devuelve el valor del slot al inicio de la tx actual.
func (o *stateObject) GetCommittedState(key types.Hash) types.Hash {
	if v, ok := o.pendingStorage[key]; ok {
		return v
	}
	if v, ok := o.originStorage[key]; ok {
		return v
	}
	// Una cuenta sin almacenamiento no necesita consultar el trie.
	if o.data.StorageRoot == types.EmptyRootHash && o.trie == nil {
		return types.Hash{}
	}
	tr, err := o.getTrie()
	if err != nil {
		o.db.setError(err)
		return types.Hash{}
	}
	v, err := tr.GetStorage(key)
	if err != nil {
		o.db.setError(err)
		return types.Hash{}
	}
	o.originStorage[key] = v
	return v
}

// SetState escribe un slot registrándolo en el journal.
func (o *stateObject) SetState(key, value types.Hash) {
	prev, prevDirt := o.dirtyStorage[key]
	if !prevDirt {
		prev = o.GetCommittedState(key)
	}
	if prev == value {
		return // sin cambio: no se ensucia el journal
	}
	o.db.journal.append(storageChange{account: o.address, key: key, prev: prev, prevDirt: prevDirt})
	o.dirtyStorage[key] = value
}

// finalise pasa el almacenamiento de la tx a "pendiente" (fin de tx).
func (o *stateObject) finalise() {
	for k, v := range o.dirtyStorage {
		o.pendingStorage[k] = v
	}
	if len(o.dirtyStorage) > 0 {
		o.dirtyStorage = make(Storage)
	}
	o.newContract = false
}

// updateTrie aplica el almacenamiento pendiente al trie.
func (o *stateObject) updateTrie() (*SecureTrie, error) {
	if len(o.pendingStorage) == 0 {
		return o.trie, nil
	}
	tr, err := o.getTrie()
	if err != nil {
		return nil, err
	}
	for k, v := range o.pendingStorage {
		if orig, ok := o.originStorage[k]; ok && orig == v {
			continue // sin cambio real respecto al trie
		}
		if err := tr.UpdateStorage(k, v); err != nil {
			return nil, err
		}
		o.originStorage[k] = v
	}
	o.pendingStorage = make(Storage)
	return tr, nil
}

// updateRoot aplica el almacenamiento y recalcula StorageRoot.
func (o *stateObject) updateRoot() error {
	tr, err := o.updateTrie()
	if err != nil {
		return err
	}
	if tr != nil {
		o.data.StorageRoot = tr.Hash()
	}
	return nil
}

// commit confirma el trie de almacenamiento devolviendo sus nodos nuevos.
func (o *stateObject) commit() (*NodeSet, error) {
	if err := o.updateRoot(); err != nil {
		return nil, err
	}
	if o.trie == nil {
		return nil, nil
	}
	root, set := o.trie.Commit()
	o.data.StorageRoot = root
	return set, nil
}

// setBalance cambia el saldo sin journal (lo usan los revert).
func (o *stateObject) setBalance(a types.Amount) { o.data.Balance = a }

// setNonce cambia el nonce sin journal.
func (o *stateObject) setNonce(n uint64) { o.data.Nonce = n }

// SetBalance cambia el saldo con journal.
func (o *stateObject) SetBalance(a types.Amount) {
	o.db.journal.append(balanceChange{account: o.address, prev: o.data.Balance})
	o.setBalance(a)
}

// SetNonce cambia el nonce con journal.
func (o *stateObject) SetNonce(n uint64) {
	o.db.journal.append(nonceChange{account: o.address, prev: o.data.Nonce})
	o.setNonce(n)
}

// Code devuelve el bytecode (cargándolo si hace falta).
func (o *stateObject) Code() []byte {
	if o.code != nil {
		return o.code
	}
	if o.data.CodeHash == types.EmptyCodeHash {
		return nil
	}
	code, err := o.db.db.ContractCode(o.data.CodeHash)
	if err != nil {
		o.db.setError(err)
		return nil
	}
	o.code = code
	return code
}

// SetCode instala código con journal.
func (o *stateObject) SetCode(code []byte) {
	o.db.journal.append(codeChange{account: o.address, prevCode: o.Code(), prevHash: o.data.CodeHash, prevDirt: o.dirtyCode})
	o.code = copyBytes(code)
	o.data.CodeHash = types.Keccak256Hash(code)
	o.dirtyCode = true
}

// deepCopy copia el objeto para otro StateDB.
func (o *stateObject) deepCopy(db *StateDB) *stateObject {
	c := *o
	c.db = db
	c.data = *o.data.Copy()
	if o.trie != nil {
		c.trie = o.trie.Copy()
	}
	c.originStorage = o.originStorage.Copy()
	c.pendingStorage = o.pendingStorage.Copy()
	c.dirtyStorage = o.dirtyStorage.Copy()
	return &c
}
