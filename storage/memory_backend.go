package storage

// Backend en memoria: un mapa protegido por RWMutex. Lo usan los tests, los
// nodos efímeros (--dev sin datadir) y la verificación de génesis. Las
// iteraciones ordenan las claves en el momento de crear el iterador, por lo
// que son O(n log n); suficiente para los volúmenes de prueba.

import (
	"fmt"
	"slices"
	"strings"
	"sync"
)

// MemoryDB es un KeyValueStore en memoria, seguro para uso concurrente.
type MemoryDB struct {
	mu     sync.RWMutex
	data   map[string][]byte
	closed bool
}

// NewMemoryDB crea una base en memoria vacía.
func NewMemoryDB() *MemoryDB { return &MemoryDB{data: make(map[string][]byte)} }

// Has implementa KeyValueReader.
func (m *MemoryDB) Has(key []byte) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return false, ErrClosed
	}
	_, ok := m.data[string(key)]
	return ok, nil
}

// Get implementa KeyValueReader.
func (m *MemoryDB) Get(key []byte) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return nil, ErrClosed
	}
	v, ok := m.data[string(key)]
	if !ok {
		return nil, ErrNotFound
	}
	return copyBytes(v), nil
}

// Put implementa KeyValueWriter.
func (m *MemoryDB) Put(key, value []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrClosed
	}
	m.data[string(key)] = append([]byte{}, value...) // nunca nil: distingue "vacío" de "ausente"
	return nil
}

// Delete implementa KeyValueWriter.
func (m *MemoryDB) Delete(key []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrClosed
	}
	delete(m.data, string(key))
	return nil
}

// Len devuelve el número de claves almacenadas.
func (m *MemoryDB) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.data)
}

// NewIterator implementa Iteratee. El iterador trabaja sobre una copia de
// las claves/valores coincidentes, así que no ve escrituras posteriores.
func (m *MemoryDB) NewIterator(prefix, start []byte) Iterator {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return &sliceIterator{err: ErrClosed}
	}
	return newSliceIterator(m.data, prefix, start)
}

// newSliceIterator filtra, ordena y copia los pares del mapa.
func newSliceIterator(data map[string][]byte, prefix, start []byte) *sliceIterator {
	p := string(prefix)
	from := string(prefix) + string(start)
	var keys []string
	for k := range data {
		if strings.HasPrefix(k, p) && k >= from {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	it := &sliceIterator{keys: make([][]byte, len(keys)), vals: make([][]byte, len(keys)), pos: -1}
	for i, k := range keys {
		it.keys[i] = []byte(k)
		it.vals[i] = copyBytes(data[k])
	}
	return it
}

// sliceIterator recorre pares ya materializados en memoria.
type sliceIterator struct {
	keys, vals [][]byte
	pos        int
	err        error
}

// Next implementa Iterator.
func (it *sliceIterator) Next() bool {
	if it.err != nil || it.pos+1 >= len(it.keys) {
		it.pos = len(it.keys)
		return false
	}
	it.pos++
	return true
}

// Key implementa Iterator.
func (it *sliceIterator) Key() []byte {
	if it.pos < 0 || it.pos >= len(it.keys) {
		return nil
	}
	return it.keys[it.pos]
}

// Value implementa Iterator.
func (it *sliceIterator) Value() []byte {
	if it.pos < 0 || it.pos >= len(it.vals) {
		return nil
	}
	return it.vals[it.pos]
}

// Error implementa Iterator.
func (it *sliceIterator) Error() error { return it.err }

// Release implementa Iterator.
func (it *sliceIterator) Release() { it.keys, it.vals = nil, nil }

// NewBatch implementa Batcher.
func (m *MemoryDB) NewBatch() Batch { return newOpBatch(m.applyOps) }

// applyOps aplica las operaciones de un lote bajo un único lock (atomicidad).
func (m *MemoryDB) applyOps(ops []batchOp) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrClosed
	}
	for _, op := range ops {
		if op.delete {
			delete(m.data, string(op.key))
		} else {
			m.data[string(op.key)] = copyBytes(op.value)
		}
	}
	return nil
}

// NewSnapshot implementa Snapshotter copiando el mapa completo (O(n)).
func (m *MemoryDB) NewSnapshot() (Snapshot, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return nil, ErrClosed
	}
	cp := make(map[string][]byte, len(m.data))
	for k, v := range m.data {
		cp[k] = v // los valores nunca se mutan in situ, basta copiar la referencia
	}
	return &memSnapshot{data: cp}, nil
}

// memSnapshot es una copia inmutable del mapa.
type memSnapshot struct{ data map[string][]byte }

// Has implementa Snapshot.
func (s *memSnapshot) Has(key []byte) (bool, error) { _, ok := s.data[string(key)]; return ok, nil }

// Get implementa Snapshot.
func (s *memSnapshot) Get(key []byte) ([]byte, error) {
	v, ok := s.data[string(key)]
	if !ok {
		return nil, ErrNotFound
	}
	return copyBytes(v), nil
}

// NewIterator implementa Snapshot.
func (s *memSnapshot) NewIterator(prefix, start []byte) Iterator {
	return newSliceIterator(s.data, prefix, start)
}

// Release implementa Snapshot.
func (s *memSnapshot) Release() { s.data = nil }

// Compact implementa Compacter (no-op en memoria).
func (m *MemoryDB) Compact(start, limit []byte) error { return nil }

// Stat implementa Stater.
func (m *MemoryDB) Stat() (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	size := 0
	for k, v := range m.data {
		size += len(k) + len(v)
	}
	return fmt.Sprintf("memorydb: %d claves, %d bytes", len(m.data), size), nil
}

// Close implementa io.Closer; libera el mapa.
func (m *MemoryDB) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	m.data = nil
	return nil
}
