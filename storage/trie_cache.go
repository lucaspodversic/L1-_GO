package storage

// Caché y base de datos de nodos del trie.
//
//   - LRU: caché genérica con límite por número de entradas o por "coste"
//     (bytes), usada también por BlockStore y el caché de código.
//   - NodeSet: los nodos nuevos producidos por un Trie.Commit.
//   - NodeDatabase: capa intermedia entre los tries y el disco. Los nodos
//     confirmados se acumulan en memoria ("dirty") y se vuelcan en lote con
//     Flush; las lecturas pasan por una caché LRU limitada en bytes. Así,
//     ejecutar varios bloques seguidos no escribe en disco los nodos
//     intermedios que el bloque siguiente sobrescribe... salvo en Flush.

import (
	"container/list"
	"errors"
	"fmt"
	"sync"

	"github.com/l1/l1/types"
)

// LRU es una caché "menos usado recientemente" segura para concurrencia.
type LRU[K comparable, V any] struct {
	mu      sync.Mutex
	ll      *list.List
	items   map[K]*list.Element
	maxCost int
	cost    int
	costFn  func(V) int
	hits    uint64
	misses  uint64
}

// lruEntry es el contenido de cada elemento de la lista.
type lruEntry[K comparable, V any] struct {
	key  K
	val  V
	cost int
}

// NewLRU crea una caché de como máximo size entradas.
func NewLRU[K comparable, V any](size int) *LRU[K, V] {
	return NewCostLRU[K, V](size, nil)
}

// NewCostLRU crea una caché cuyo coste total no supera maxCost; costFn
// mide cada valor (nil = coste 1 por entrada).
func NewCostLRU[K comparable, V any](maxCost int, costFn func(V) int) *LRU[K, V] {
	if maxCost <= 0 {
		maxCost = 1
	}
	return &LRU[K, V]{ll: list.New(), items: make(map[K]*list.Element), maxCost: maxCost, costFn: costFn}
}

// Get busca una clave y la marca como usada recientemente.
func (c *LRU[K, V]) Get(k K) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.items[k]; ok {
		c.ll.MoveToFront(e)
		c.hits++
		return e.Value.(*lruEntry[K, V]).val, true
	}
	c.misses++
	var zero V
	return zero, false
}

// Contains informa si la clave está, sin alterar el orden.
func (c *LRU[K, V]) Contains(k K) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.items[k]
	return ok
}

// Add inserta o actualiza y expulsa lo más antiguo si se supera el límite.
func (c *LRU[K, V]) Add(k K, v V) {
	cost := 1
	if c.costFn != nil {
		cost = c.costFn(v)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if cost > c.maxCost {
		return // nunca cabría: no se cachea
	}
	if e, ok := c.items[k]; ok {
		ent := e.Value.(*lruEntry[K, V])
		c.cost += cost - ent.cost
		ent.val, ent.cost = v, cost
		c.ll.MoveToFront(e)
	} else {
		c.items[k] = c.ll.PushFront(&lruEntry[K, V]{key: k, val: v, cost: cost})
		c.cost += cost
	}
	for c.cost > c.maxCost {
		c.removeElement(c.ll.Back())
	}
}

// Remove elimina una clave.
func (c *LRU[K, V]) Remove(k K) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.items[k]; ok {
		c.removeElement(e)
	}
}

// removeElement quita un elemento (con el lock tomado).
func (c *LRU[K, V]) removeElement(e *list.Element) {
	ent := e.Value.(*lruEntry[K, V])
	c.ll.Remove(e)
	delete(c.items, ent.key)
	c.cost -= ent.cost
}

// Len devuelve el número de entradas.
func (c *LRU[K, V]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}

// Cost devuelve el coste total actual.
func (c *LRU[K, V]) Cost() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cost
}

// Stats devuelve aciertos y fallos acumulados.
func (c *LRU[K, V]) Stats() (hits, misses uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hits, c.misses
}

// Purge vacía la caché.
func (c *LRU[K, V]) Purge() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ll.Init()
	c.items = make(map[K]*list.Element)
	c.cost = 0
}

// ---------------------------------------------------------------------
// NodeSet y NodeDatabase
// ---------------------------------------------------------------------

// NodeReader es lo mínimo que un Trie necesita para cargar nodos.
type NodeReader interface {
	// Node devuelve la codificación RLP del nodo con ese hash.
	Node(hash types.Hash) ([]byte, error)
}

// MissingNodeError indica que un nodo referenciado no está disponible
// (base podada o incompleta).
type MissingNodeError struct {
	// NodeHash es el hash buscado.
	NodeHash types.Hash
	// Path es la ruta hex (nibbles) donde se esperaba.
	Path []byte
}

// Error implementa error.
func (e *MissingNodeError) Error() string {
	return fmt.Sprintf("trie: falta el nodo %x (ruta %x)", e.NodeHash[:], e.Path)
}

// NodeSet agrupa los nodos producidos por uno o varios Commit.
type NodeSet struct {
	// Nodes mapea hash → RLP.
	Nodes map[types.Hash][]byte
	// Preimages mapea hash de clave → clave original (tries seguros).
	Preimages map[types.Hash][]byte
}

// NewNodeSet crea un conjunto vacío.
func NewNodeSet() *NodeSet {
	return &NodeSet{Nodes: make(map[types.Hash][]byte), Preimages: make(map[types.Hash][]byte)}
}

// Merge incorpora otro conjunto.
func (s *NodeSet) Merge(o *NodeSet) {
	if o == nil {
		return
	}
	for h, n := range o.Nodes {
		s.Nodes[h] = n
	}
	for h, p := range o.Preimages {
		s.Preimages[h] = p
	}
}

// Size devuelve el volumen aproximado en bytes.
func (s *NodeSet) Size() int {
	n := 0
	for _, v := range s.Nodes {
		n += len(v) + 32
	}
	for _, v := range s.Preimages {
		n += len(v) + 32
	}
	return n
}

// NodeDatabase cachea nodos del trie sobre un KeyValueStore.
type NodeDatabase struct {
	disk      KeyValueStore
	mu        sync.RWMutex
	dirties   map[types.Hash][]byte // confirmados, aún no en disco
	preimages map[types.Hash][]byte
	dirtySize int
	cleans    *LRU[types.Hash, []byte]
}

// NewNodeDatabase crea la base de nodos con una caché limpia de cacheMB MiB.
func NewNodeDatabase(disk KeyValueStore, cacheMB int) *NodeDatabase {
	if cacheMB <= 0 {
		cacheMB = 16
	}
	return &NodeDatabase{
		disk:      disk,
		dirties:   make(map[types.Hash][]byte),
		preimages: make(map[types.Hash][]byte),
		cleans:    NewCostLRU[types.Hash, []byte](cacheMB*1024*1024, func(b []byte) int { return len(b) + 32 }),
	}
}

// Disk devuelve el backend.
func (db *NodeDatabase) Disk() KeyValueStore { return db.disk }

// Node implementa NodeReader: memoria sucia → caché limpia → disco.
func (db *NodeDatabase) Node(hash types.Hash) ([]byte, error) {
	db.mu.RLock()
	if n, ok := db.dirties[hash]; ok {
		db.mu.RUnlock()
		return n, nil
	}
	db.mu.RUnlock()
	if n, ok := db.cleans.Get(hash); ok {
		return n, nil
	}
	n, err := db.disk.Get(trieNodeKey(hash))
	if errors.Is(err, ErrNotFound) {
		return nil, &MissingNodeError{NodeHash: hash}
	}
	if err != nil {
		return nil, err
	}
	db.cleans.Add(hash, n)
	return n, nil
}

// HasNode informa si el nodo está disponible.
func (db *NodeDatabase) HasNode(hash types.Hash) bool {
	_, err := db.Node(hash)
	return err == nil
}

// Update incorpora los nodos de un commit a la memoria sucia.
func (db *NodeDatabase) Update(set *NodeSet) {
	if set == nil {
		return
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	for h, n := range set.Nodes {
		if _, ok := db.dirties[h]; !ok {
			db.dirties[h] = n
			db.dirtySize += len(n) + 32
		}
	}
	for h, p := range set.Preimages {
		db.preimages[h] = p
	}
}

// DirtySize devuelve los bytes pendientes de volcar.
func (db *NodeDatabase) DirtySize() int {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return db.dirtySize
}

// Flush escribe en disco todos los nodos sucios y las preimágenes en
// lotes y los pasa a la caché limpia.
func (db *NodeDatabase) Flush() error {
	db.mu.Lock()
	defer db.mu.Unlock()
	w := NewBatchWriter(db.disk, 0)
	for h, n := range db.dirties {
		if err := w.Put(trieNodeKey(h), n); err != nil {
			return err
		}
	}
	for h, p := range db.preimages {
		if err := w.Put(preimageKey(h), p); err != nil {
			return err
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}
	for h, n := range db.dirties {
		db.cleans.Add(h, n)
	}
	db.dirties = make(map[types.Hash][]byte)
	db.preimages = make(map[types.Hash][]byte)
	db.dirtySize = 0
	return nil
}

// Commit es un alias de Flush (nombre usado por la cadena al finalizar).
func (db *NodeDatabase) Commit() error { return db.Flush() }

// Preimage devuelve la clave original de un hash del trie seguro.
func (db *NodeDatabase) Preimage(hash types.Hash) ([]byte, bool) {
	db.mu.RLock()
	p, ok := db.preimages[hash]
	db.mu.RUnlock()
	if ok {
		return p, true
	}
	v, err := db.disk.Get(preimageKey(hash))
	return v, err == nil
}

// ResetCache vacía la caché limpia (necesario tras podar nodos del disco).
func (db *NodeDatabase) ResetCache() { db.cleans.Purge() }

// CacheStats devuelve aciertos/fallos de la caché limpia.
func (db *NodeDatabase) CacheStats() (hits, misses uint64) { return db.cleans.Stats() }
