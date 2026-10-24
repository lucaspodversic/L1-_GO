package storage

// Trie "seguro": las claves se hashean con Keccak256 antes de insertarse.
// Así la profundidad del trie queda acotada (claves de 32 bytes uniformes)
// y un atacante no puede crear ramas profundas eligiendo direcciones o slots
// con prefijos comunes. Se usa tanto para el trie de cuentas (clave =
// keccak(dirección)) como para el almacenamiento de cada contrato (clave =
// keccak(slot)), exactamente como en Ethereum.

import (
	"github.com/l1/l1/types"
)

// SecureTrie envuelve un Trie hasheando las claves.
type SecureTrie struct {
	trie Trie
	// preimages guarda hash → clave original de las claves escritas, para
	// poder enumerar el estado por dirección (depuración, exportación).
	preimages map[types.Hash][]byte
	// owner es el hash de la cuenta dueña (cero para el trie de cuentas);
	// sólo informativo para errores.
	owner types.Hash
}

// NewSecureTrie abre un trie seguro con la raíz dada.
func NewSecureTrie(owner, root types.Hash, db NodeReader) (*SecureTrie, error) {
	t, err := NewTrie(root, db)
	if err != nil {
		return nil, err
	}
	return &SecureTrie{trie: *t, owner: owner}, nil
}

// hashKey hashea una clave y registra su preimagen.
func (t *SecureTrie) hashKey(key []byte) []byte {
	h := types.Keccak256Hash(key)
	if t.preimages == nil {
		t.preimages = make(map[types.Hash][]byte)
	}
	if _, ok := t.preimages[h]; !ok {
		t.preimages[h] = copyBytes(key)
	}
	return h[:]
}

// Owner devuelve el hash de la cuenta dueña del trie.
func (t *SecureTrie) Owner() types.Hash { return t.owner }

// Get devuelve el valor de una clave original.
func (t *SecureTrie) Get(key []byte) ([]byte, error) {
	return t.trie.Get(types.Keccak256(key))
}

// Update escribe (o borra, si value está vacío) una clave original.
func (t *SecureTrie) Update(key, value []byte) error { return t.trie.Update(t.hashKey(key), value) }

// Delete borra una clave original.
func (t *SecureTrie) Delete(key []byte) error { return t.trie.Update(t.hashKey(key), nil) }

// GetAccount lee una cuenta (nil si no existe).
func (t *SecureTrie) GetAccount(addr types.Address) (*types.Account, error) {
	v, err := t.Get(addr[:])
	if err != nil || v == nil {
		return nil, err
	}
	return types.DecodeAccount(v)
}

// UpdateAccount escribe una cuenta.
func (t *SecureTrie) UpdateAccount(addr types.Address, acc *types.Account) error {
	return t.Update(addr[:], acc.EncodeRLP())
}

// DeleteAccount elimina una cuenta.
func (t *SecureTrie) DeleteAccount(addr types.Address) error { return t.Delete(addr[:]) }

// GetStorage lee un slot. Los valores se guardan como RLP del entero sin
// ceros a la izquierda; aquí se devuelven como palabra de 32 bytes.
func (t *SecureTrie) GetStorage(slot types.Hash) (types.Hash, error) {
	enc, err := t.Get(slot[:])
	if err != nil || len(enc) == 0 {
		return types.Hash{}, err
	}
	it, err := types.DecodeRLP(enc)
	if err != nil {
		return types.Hash{}, err
	}
	b, err := it.Bytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.BytesToHash(b), nil
}

// UpdateStorage escribe un slot; el valor cero lo borra (Ethereum no
// almacena ceros, lo que también hace posible el reembolso de gas).
func (t *SecureTrie) UpdateStorage(slot, value types.Hash) error {
	if value == (types.Hash{}) {
		return t.Delete(slot[:])
	}
	return t.Update(slot[:], encodeStorageValue(value))
}

// DeleteStorage borra un slot.
func (t *SecureTrie) DeleteStorage(slot types.Hash) error { return t.Delete(slot[:]) }

// encodeStorageValue codifica la palabra recortando ceros a la izquierda.
func encodeStorageValue(v types.Hash) []byte {
	b := v[:]
	for len(b) > 0 && b[0] == 0 {
		b = b[1:]
	}
	return types.EncodeBytes(b)
}

// Hash devuelve la raíz.
func (t *SecureTrie) Hash() types.Hash { return t.trie.Hash() }

// Commit devuelve la raíz y los nodos nuevos (con las preimágenes).
func (t *SecureTrie) Commit() (types.Hash, *NodeSet) {
	root, set := t.trie.Commit()
	for h, p := range t.preimages {
		set.Preimages[h] = p
	}
	t.preimages = nil
	return root, set
}

// Copy devuelve una copia independiente.
func (t *SecureTrie) Copy() *SecureTrie {
	c := &SecureTrie{trie: *t.trie.Copy(), owner: t.owner}
	if t.preimages != nil {
		c.preimages = make(map[types.Hash][]byte, len(t.preimages))
		for k, v := range t.preimages {
			c.preimages[k] = v
		}
	}
	return c
}

// Prove construye la prueba de Merkle de una clave original.
func (t *SecureTrie) Prove(key []byte) ([][]byte, error) { return t.trie.Prove(types.Keccak256(key)) }

// Trie expone el trie subyacente (claves ya hasheadas).
func (t *SecureTrie) Trie() *Trie { return &t.trie }

// VerifyAccountProof verifica una prueba de cuenta contra la raíz de estado.
func VerifyAccountProof(stateRoot types.Hash, addr types.Address, proof [][]byte) (*types.Account, error) {
	v, err := VerifyProof(stateRoot, types.Keccak256(addr[:]), proof)
	if err != nil || v == nil {
		return nil, err
	}
	return types.DecodeAccount(v)
}

// VerifyStorageProof verifica la prueba de un slot contra la raíz de
// almacenamiento de la cuenta.
func VerifyStorageProof(storageRoot, slot types.Hash, proof [][]byte) (types.Hash, error) {
	v, err := VerifyProof(storageRoot, types.Keccak256(slot[:]), proof)
	if err != nil || v == nil {
		return types.Hash{}, err
	}
	it, err := types.DecodeRLP(v)
	if err != nil {
		return types.Hash{}, err
	}
	b, err := it.Bytes()
	if err != nil {
		return types.Hash{}, err
	}
	return types.BytesToHash(b), nil
}
