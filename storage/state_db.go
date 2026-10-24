package storage

// StateDB: el estado mundial que ve la máquina virtual.
//
// Es una caché de escritura sobre el trie de cuentas: las lecturas cargan
// cuentas bajo demanda en stateObjects; las escrituras se registran en el
// journal para poder revertirse (Snapshot/RevertToSnapshot); al final de
// cada transacción Finalise consolida los cambios; IntermediateRoot calcula
// la raíz de estado (para el recibo/cabecera); Commit produce los nodos a
// persistir. La API sigue de cerca la de go-ethereum para que el intérprete
// EVM-like (paquete vm) pueda implementarse con la semántica conocida:
// EIP-161 (cuentas vacías), EIP-2929/2930 (access lists), EIP-1153
// (almacenamiento transitorio), EIP-3529 (reembolsos) y EIP-6780
// (SELFDESTRUCT restringido).
//
// Un StateDB NO es seguro para uso concurrente: cada ejecución de bloque
// usa el suyo (Copy permite derivar uno independiente).

import (
	"fmt"
	"maps"

	"github.com/l1/l1/types"
)

// StateDatabase agrupa lo que comparten todos los StateDB: la base de
// nodos del trie, el disco y una caché de bytecode.
type StateDatabase struct {
	disk      KeyValueStore
	nodes     *NodeDatabase
	codeCache *LRU[types.Hash, []byte]
}

// NewStateDatabase crea la base de estado sobre una NodeDatabase.
func NewStateDatabase(nodes *NodeDatabase) *StateDatabase {
	return &StateDatabase{
		disk:      nodes.Disk(),
		nodes:     nodes,
		codeCache: NewCostLRU[types.Hash, []byte](64*1024*1024, func(b []byte) int { return len(b) + 32 }),
	}
}

// NewMemoryStateDatabase crea una base de estado efímera en memoria.
func NewMemoryStateDatabase() *StateDatabase {
	return NewStateDatabase(NewNodeDatabase(NewMemoryDB(), 16))
}

// OpenTrie abre el trie de cuentas.
func (d *StateDatabase) OpenTrie(root types.Hash) (*SecureTrie, error) {
	return NewSecureTrie(types.Hash{}, root, d.nodes)
}

// OpenStorageTrie abre el trie de almacenamiento de una cuenta.
func (d *StateDatabase) OpenStorageTrie(addrHash, root types.Hash) (*SecureTrie, error) {
	return NewSecureTrie(addrHash, root, d.nodes)
}

// ContractCode devuelve el bytecode con ese hash.
func (d *StateDatabase) ContractCode(hash types.Hash) ([]byte, error) {
	if c, ok := d.codeCache.Get(hash); ok {
		return c, nil
	}
	c, err := d.disk.Get(codeKey(hash))
	if err != nil {
		return nil, fmt.Errorf("state: código %x: %w", hash[:], err)
	}
	d.codeCache.Add(hash, c)
	return c, nil
}

// WriteCode guarda bytecode (indexado por su hash) en el escritor dado y
// en la caché.
func (d *StateDatabase) WriteCode(w KeyValueWriter, hash types.Hash, code []byte) error {
	d.codeCache.Add(hash, code)
	return w.Put(codeKey(hash), code)
}

// TrieDB devuelve la base de nodos.
func (d *StateDatabase) TrieDB() *NodeDatabase { return d.nodes }

// DiskDB devuelve el backend.
func (d *StateDatabase) DiskDB() KeyValueStore { return d.disk }

// ---------------------------------------------------------------------
// Access list (EIP-2929)
// ---------------------------------------------------------------------

// accessList registra direcciones y slots "calientes" de la tx actual.
type accessList struct {
	addresses map[types.Address]int // índice en slots, o -1 si no tiene slots
	slots     []map[types.Hash]struct{}
}

// newAccessList crea una lista vacía.
func newAccessList() *accessList { return &accessList{addresses: make(map[types.Address]int)} }

// ContainsAddress informa si la dirección está en la lista.
func (al *accessList) ContainsAddress(a types.Address) bool { _, ok := al.addresses[a]; return ok }

// Contains informa si la dirección y el slot están en la lista.
func (al *accessList) Contains(a types.Address, slot types.Hash) (addrOk, slotOk bool) {
	idx, ok := al.addresses[a]
	if !ok {
		return false, false
	}
	if idx == -1 {
		return true, false
	}
	_, slotOk = al.slots[idx][slot]
	return true, slotOk
}

// AddAddress añade una dirección; devuelve true si era nueva.
func (al *accessList) AddAddress(a types.Address) bool {
	if _, ok := al.addresses[a]; ok {
		return false
	}
	al.addresses[a] = -1
	return true
}

// AddSlot añade (dirección, slot); devuelve qué parte era nueva.
func (al *accessList) AddSlot(a types.Address, slot types.Hash) (addrChange, slotChange bool) {
	idx, ok := al.addresses[a]
	if !ok || idx == -1 {
		al.addresses[a] = len(al.slots)
		al.slots = append(al.slots, map[types.Hash]struct{}{slot: {}})
		return !ok, true
	}
	if _, ok := al.slots[idx][slot]; ok {
		return false, false
	}
	al.slots[idx][slot] = struct{}{}
	return false, true
}

// DeleteSlot deshace un AddSlot (sólo válido en orden inverso al journal).
func (al *accessList) DeleteSlot(a types.Address, slot types.Hash) {
	idx, ok := al.addresses[a]
	if !ok || idx == -1 {
		panic("accesslist: borrado de slot inexistente")
	}
	delete(al.slots[idx], slot)
	if len(al.slots[idx]) == 0 {
		// Por el orden del journal, este mapa es el último añadido.
		al.slots = al.slots[:idx]
		al.addresses[a] = -1
	}
}

// DeleteAddress deshace un AddAddress.
func (al *accessList) DeleteAddress(a types.Address) { delete(al.addresses, a) }

// Copy devuelve una copia profunda.
func (al *accessList) Copy() *accessList {
	c := &accessList{addresses: maps.Clone(al.addresses), slots: make([]map[types.Hash]struct{}, len(al.slots))}
	for i, s := range al.slots {
		c.slots[i] = maps.Clone(s)
	}
	return c
}

// ---------------------------------------------------------------------
// StateDB
// ---------------------------------------------------------------------

// StateDB es el estado mundial mutable durante la ejecución.
type StateDB struct {
	db   *StateDatabase
	trie *SecureTrie
	// originalRoot es la raíz desde la que se abrió (o del último Commit).
	originalRoot types.Hash

	// stateObjects son las cuentas cargadas/modificadas.
	stateObjects map[types.Address]*stateObject
	// stateObjectsDestruct son las cuentas eliminadas en el bloque.
	stateObjectsDestruct map[types.Address]struct{}
	// stateObjectsPending: finalizadas, pendientes de aplicar al trie.
	stateObjectsPending map[types.Address]struct{}
	// stateObjectsDirty: modificadas desde el último Commit.
	stateObjectsDirty map[types.Address]struct{}

	// dbErr guarda el primer error de base de datos (la VM no puede
	// propagar errores de I/O en mitad de un opcode; se consulta al final).
	dbErr error

	refund  uint64
	thash   types.Hash
	txIndex int
	logs    map[types.Hash][]*types.Log
	logSize uint

	accessList       *accessList
	transientStorage map[types.Address]Storage

	journal        *journal
	validRevisions []revision
	nextRevisionID int
}

// New abre un StateDB sobre la raíz dada.
func New(root types.Hash, db *StateDatabase) (*StateDB, error) {
	tr, err := db.OpenTrie(root)
	if err != nil {
		return nil, err
	}
	return &StateDB{
		db: db, trie: tr, originalRoot: root,
		stateObjects:         make(map[types.Address]*stateObject),
		stateObjectsDestruct: make(map[types.Address]struct{}),
		stateObjectsPending:  make(map[types.Address]struct{}),
		stateObjectsDirty:    make(map[types.Address]struct{}),
		logs:                 make(map[types.Hash][]*types.Log),
		accessList:           newAccessList(),
		transientStorage:     make(map[types.Address]Storage),
		journal:              newJournal(),
	}, nil
}

// Database devuelve la StateDatabase subyacente.
func (s *StateDB) Database() *StateDatabase { return s.db }

// OriginalRoot devuelve la raíz de partida.
func (s *StateDB) OriginalRoot() types.Hash { return s.originalRoot }

// setError recuerda el primer error.
func (s *StateDB) setError(err error) {
	if s.dbErr == nil {
		s.dbErr = err
	}
}

// Error devuelve el primer error de base de datos ocurrido.
func (s *StateDB) Error() error { return s.dbErr }

// getStateObject devuelve la cuenta viva (nil si no existe o se borró).
func (s *StateDB) getStateObject(addr types.Address) *stateObject {
	if obj, ok := s.stateObjects[addr]; ok {
		if obj.deleted {
			return nil
		}
		return obj
	}
	if _, destructed := s.stateObjectsDestruct[addr]; destructed {
		return nil // borrada en una tx anterior del bloque (aún en el trie)
	}
	acc, err := s.trie.GetAccount(addr)
	if err != nil {
		s.setError(fmt.Errorf("state: leyendo cuenta %s: %w", addr, err))
		return nil
	}
	if acc == nil {
		return nil
	}
	obj := newObject(s, addr, acc)
	s.stateObjects[addr] = obj
	return obj
}

// getOrNewStateObject devuelve la cuenta, creándola si no existe.
func (s *StateDB) getOrNewStateObject(addr types.Address) *stateObject {
	if obj := s.getStateObject(addr); obj != nil {
		return obj
	}
	obj, _ := s.createObject(addr)
	return obj
}

// createObject crea una cuenta nueva (sustituyendo la existente si la hay).
func (s *StateDB) createObject(addr types.Address) (newobj, prev *stateObject) {
	prev = s.getStateObject(addr)
	newobj = newObject(s, addr, nil)
	if prev == nil {
		s.journal.append(createObjectChange{account: addr})
	} else {
		s.journal.append(resetObjectChange{account: addr, prev: prev})
	}
	s.stateObjects[addr] = newobj
	return newobj, prev
}

// CreateAccount crea (o reinicia) una cuenta conservando el saldo previo
// (alguien pudo enviar fondos a la dirección antes de desplegar el contrato).
func (s *StateDB) CreateAccount(addr types.Address) {
	newobj, prev := s.createObject(addr)
	if prev != nil {
		newobj.setBalance(prev.data.Balance)
	}
}

// CreateContract marca la cuenta como contrato creado en esta tx (EIP-6780).
// Debe llamarse tras CreateAccount en CREATE/CREATE2.
func (s *StateDB) CreateContract(addr types.Address) {
	obj := s.getOrNewStateObject(addr)
	if !obj.newContract {
		obj.newContract = true
		s.journal.append(createContractChange{account: addr})
	}
}

// Exist informa si la cuenta existe (aunque esté vacía).
func (s *StateDB) Exist(addr types.Address) bool { return s.getStateObject(addr) != nil }

// Empty informa si la cuenta no existe o está vacía (EIP-161).
func (s *StateDB) Empty(addr types.Address) bool {
	obj := s.getStateObject(addr)
	return obj == nil || obj.empty()
}

// GetBalance devuelve el saldo (cero si no existe).
func (s *StateDB) GetBalance(addr types.Address) types.Amount {
	if obj := s.getStateObject(addr); obj != nil {
		return obj.data.Balance
	}
	return types.Amount{}
}

// AddBalance suma al saldo. Sumar cero sigue "tocando" la cuenta, lo que
// importa para la eliminación de cuentas vacías.
func (s *StateDB) AddBalance(addr types.Address, amount types.Amount) {
	obj := s.getOrNewStateObject(addr)
	if amount.IsZero() {
		obj.touch()
		return
	}
	obj.SetBalance(obj.data.Balance.Add(amount))
}

// SubBalance resta del saldo. Devuelve error si no hay fondos suficientes
// (sin modificar nada); la VM debe comprobarlo antes de transferir.
func (s *StateDB) SubBalance(addr types.Address, amount types.Amount) error {
	obj := s.getOrNewStateObject(addr)
	if amount.IsZero() {
		obj.touch()
		return nil
	}
	nb, err := obj.data.Balance.CheckedSub(amount)
	if err != nil {
		return fmt.Errorf("state: saldo insuficiente en %s: %w", addr, err)
	}
	obj.SetBalance(nb)
	return nil
}

// SetBalance fija el saldo.
func (s *StateDB) SetBalance(addr types.Address, amount types.Amount) {
	s.getOrNewStateObject(addr).SetBalance(amount)
}

// GetNonce devuelve el nonce (0 si no existe).
func (s *StateDB) GetNonce(addr types.Address) uint64 {
	if obj := s.getStateObject(addr); obj != nil {
		return obj.data.Nonce
	}
	return 0
}

// SetNonce fija el nonce.
func (s *StateDB) SetNonce(addr types.Address, n uint64) { s.getOrNewStateObject(addr).SetNonce(n) }

// GetCode devuelve el bytecode.
func (s *StateDB) GetCode(addr types.Address) []byte {
	if obj := s.getStateObject(addr); obj != nil {
		return obj.Code()
	}
	return nil
}

// GetCodeSize devuelve la longitud del bytecode.
func (s *StateDB) GetCodeSize(addr types.Address) int { return len(s.GetCode(addr)) }

// GetCodeHash devuelve el hash del código; cero si la cuenta no existe
// (semántica de EXTCODEHASH de EIP-1052).
func (s *StateDB) GetCodeHash(addr types.Address) types.Hash {
	if obj := s.getStateObject(addr); obj != nil {
		return obj.data.CodeHash
	}
	return types.Hash{}
}

// SetCode instala bytecode.
func (s *StateDB) SetCode(addr types.Address, code []byte) { s.getOrNewStateObject(addr).SetCode(code) }

// GetState devuelve el valor actual de un slot.
func (s *StateDB) GetState(addr types.Address, key types.Hash) types.Hash {
	if obj := s.getStateObject(addr); obj != nil {
		return obj.GetState(key)
	}
	return types.Hash{}
}

// GetCommittedState devuelve el valor del slot al inicio de la tx.
func (s *StateDB) GetCommittedState(addr types.Address, key types.Hash) types.Hash {
	if obj := s.getStateObject(addr); obj != nil {
		return obj.GetCommittedState(key)
	}
	return types.Hash{}
}

// SetState escribe un slot.
func (s *StateDB) SetState(addr types.Address, key, value types.Hash) {
	s.getOrNewStateObject(addr).SetState(key, value)
}

// GetStorageRoot devuelve la raíz de almacenamiento confirmada de la cuenta.
func (s *StateDB) GetStorageRoot(addr types.Address) types.Hash {
	if obj := s.getStateObject(addr); obj != nil {
		return obj.data.StorageRoot
	}
	return types.Hash{}
}

// GetAccount devuelve una copia del estado de consenso de la cuenta.
func (s *StateDB) GetAccount(addr types.Address) *types.Account {
	if obj := s.getStateObject(addr); obj != nil {
		return obj.data.Copy()
	}
	return nil
}

// GetTransientState lee almacenamiento transitorio (TLOAD, EIP-1153).
func (s *StateDB) GetTransientState(addr types.Address, key types.Hash) types.Hash {
	return s.transientStorage[addr][key]
}

// SetTransientState escribe almacenamiento transitorio (TSTORE).
func (s *StateDB) SetTransientState(addr types.Address, key, value types.Hash) {
	prev := s.GetTransientState(addr, key)
	if prev == value {
		return
	}
	s.journal.append(transientStorageChange{account: addr, key: key, prevalue: prev})
	s.setTransientState(addr, key, value)
}

// setTransientState escribe sin journal.
func (s *StateDB) setTransientState(addr types.Address, key, value types.Hash) {
	m, ok := s.transientStorage[addr]
	if !ok {
		m = make(Storage)
		s.transientStorage[addr] = m
	}
	if value == (types.Hash{}) {
		delete(m, key)
	} else {
		m[key] = value
	}
}

// SelfDestruct marca la cuenta para borrado al final de la tx y pone su
// saldo a cero (el llamador debe haber transferido antes el saldo).
func (s *StateDB) SelfDestruct(addr types.Address) {
	obj := s.getStateObject(addr)
	if obj == nil {
		return
	}
	s.journal.append(selfDestructChange{account: addr, prev: obj.selfDestructed, prevBalance: obj.data.Balance})
	obj.selfDestructed = true
	obj.setBalance(types.Amount{})
}

// SelfDestruct6780 aplica EIP-6780: sólo borra si la cuenta se creó en la
// misma transacción. Devuelve si se marcó para borrado.
func (s *StateDB) SelfDestruct6780(addr types.Address) bool {
	obj := s.getStateObject(addr)
	if obj == nil || !obj.newContract {
		return false
	}
	s.SelfDestruct(addr)
	return true
}

// HasSelfDestructed informa si la cuenta ejecutó SELFDESTRUCT en esta tx.
func (s *StateDB) HasSelfDestructed(addr types.Address) bool {
	obj := s.getStateObject(addr)
	return obj != nil && obj.selfDestructed
}

// AddRefund suma al contador de reembolso de gas.
func (s *StateDB) AddRefund(gas uint64) {
	s.journal.append(refundChange{prev: s.refund})
	s.refund += gas
}

// SubRefund resta del contador; un desbordamiento indica un bug de la VM.
func (s *StateDB) SubRefund(gas uint64) {
	s.journal.append(refundChange{prev: s.refund})
	if gas > s.refund {
		panic(fmt.Sprintf("state: reembolso negativo (%d > %d)", gas, s.refund))
	}
	s.refund -= gas
}

// GetRefund devuelve el contador de reembolso.
func (s *StateDB) GetRefund() uint64 { return s.refund }

// SetTxContext fija la tx en curso (para asociarle los logs).
func (s *StateDB) SetTxContext(thash types.Hash, ti int) { s.thash, s.txIndex = thash, ti }

// TxIndex devuelve el índice de la tx en curso.
func (s *StateDB) TxIndex() int { return s.txIndex }

// AddLog registra un log emitido por la VM.
func (s *StateDB) AddLog(l *types.Log) {
	s.journal.append(addLogChange{txHash: s.thash})
	l.TxHash, l.TxIndex, l.Index = s.thash, uint(s.txIndex), s.logSize
	s.logs[s.thash] = append(s.logs[s.thash], l)
	s.logSize++
}

// GetLogs devuelve los logs de una tx completando los datos del bloque.
func (s *StateDB) GetLogs(txHash types.Hash, blockNumber uint64, blockHash types.Hash) []*types.Log {
	logs := s.logs[txHash]
	for _, l := range logs {
		l.BlockNumber, l.BlockHash = blockNumber, blockHash
	}
	return logs
}

// Logs devuelve todos los logs del bloque en orden de emisión.
func (s *StateDB) Logs() []*types.Log {
	out := make([]*types.Log, s.logSize)
	for _, ls := range s.logs {
		for _, l := range ls {
			if int(l.Index) < len(out) {
				out[l.Index] = l
			}
		}
	}
	return out
}

// Prepare inicializa el contexto de una tx (Berlin/Shanghai/Cancún):
// access list con emisor, destino, precompilados, coinbase (EIP-3651) y la
// access list declarada en la tx; y vacía el almacenamiento transitorio.
func (s *StateDB) Prepare(sender, coinbase types.Address, dst *types.Address, precompiles []types.Address, list types.AccessList) {
	al := newAccessList()
	s.accessList = al
	al.AddAddress(sender)
	if dst != nil {
		al.AddAddress(*dst)
	}
	for _, p := range precompiles {
		al.AddAddress(p)
	}
	for _, el := range list {
		al.AddAddress(el.Address)
		for _, k := range el.StorageKeys {
			al.AddSlot(el.Address, k)
		}
	}
	al.AddAddress(coinbase)
	s.transientStorage = make(map[types.Address]Storage)
}

// AddAddressToAccessList calienta una dirección.
func (s *StateDB) AddAddressToAccessList(addr types.Address) {
	if s.accessList.AddAddress(addr) {
		s.journal.append(accessListAddAccountChange{address: addr})
	}
}

// AddSlotToAccessList calienta un slot (y su dirección).
func (s *StateDB) AddSlotToAccessList(addr types.Address, slot types.Hash) {
	addrMod, slotMod := s.accessList.AddSlot(addr, slot)
	if addrMod {
		// Se registran por separado para que el revert deshaga en orden.
		s.journal.append(accessListAddAccountChange{address: addr})
	}
	if slotMod {
		s.journal.append(accessListAddSlotChange{address: addr, slot: slot})
	}
}

// AddressInAccessList informa si la dirección está caliente.
func (s *StateDB) AddressInAccessList(addr types.Address) bool {
	return s.accessList.ContainsAddress(addr)
}

// SlotInAccessList informa si la dirección y el slot están calientes.
func (s *StateDB) SlotInAccessList(addr types.Address, slot types.Hash) (addressOk, slotOk bool) {
	return s.accessList.Contains(addr, slot)
}

// ForEachStorage recorre el almacenamiento confirmado de una cuenta
// aplicando encima los cambios en memoria. cb devuelve false para parar.
func (s *StateDB) ForEachStorage(addr types.Address, cb func(key, value types.Hash) bool) error {
	obj := s.getStateObject(addr)
	if obj == nil {
		return nil
	}
	tr, err := obj.getTrie()
	if err != nil {
		return err
	}
	seen := make(map[types.Hash]struct{})
	// Primero lo que hay en memoria (valor más reciente).
	for _, m := range []Storage{obj.dirtyStorage, obj.pendingStorage} {
		for k, v := range m {
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			if v != (types.Hash{}) && !cb(k, v) {
				return nil
			}
		}
	}
	stop := false
	return tr.Trie().Walk(func(hk, raw []byte) error {
		if stop {
			return nil
		}
		pre, ok := s.db.nodes.Preimage(types.BytesToHash(hk))
		if !ok {
			pre, ok = tr.preimages[types.BytesToHash(hk)]
		}
		if !ok {
			return nil // sin preimagen no se conoce el slot original
		}
		key := types.BytesToHash(pre)
		if _, ok := seen[key]; ok {
			return nil
		}
		it, err := types.DecodeRLP(raw)
		if err != nil {
			return err
		}
		b, _ := it.Bytes()
		if !cb(key, types.BytesToHash(b)) {
			stop = true
		}
		return nil
	})
}

// Copy devuelve un StateDB independiente con el mismo contenido. El
// journal no se copia: los snapshots tomados en el original no son
// válidos en la copia (pero las cuentas modificadas siguen marcadas).
func (s *StateDB) Copy() *StateDB {
	c := &StateDB{
		db: s.db, trie: s.trie.Copy(), originalRoot: s.originalRoot,
		stateObjects:         make(map[types.Address]*stateObject, len(s.stateObjects)),
		stateObjectsDestruct: maps.Clone(s.stateObjectsDestruct),
		stateObjectsPending:  maps.Clone(s.stateObjectsPending),
		stateObjectsDirty:    maps.Clone(s.stateObjectsDirty),
		dbErr:                s.dbErr,
		refund:               s.refund,
		thash:                s.thash, txIndex: s.txIndex,
		logs:             make(map[types.Hash][]*types.Log, len(s.logs)),
		logSize:          s.logSize,
		accessList:       s.accessList.Copy(),
		transientStorage: make(map[types.Address]Storage, len(s.transientStorage)),
		journal:          newJournal(),
	}
	for a, obj := range s.stateObjects {
		c.stateObjects[a] = obj.deepCopy(c)
	}
	for a := range s.journal.dirties {
		c.journal.dirty(a)
	}
	for h, ls := range s.logs {
		cp := make([]*types.Log, len(ls))
		for i, l := range ls {
			lc := *l
			cp[i] = &lc
		}
		c.logs[h] = cp
	}
	for a, st := range s.transientStorage {
		c.transientStorage[a] = st.Copy()
	}
	return c
}
