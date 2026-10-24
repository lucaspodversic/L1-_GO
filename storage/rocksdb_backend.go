package storage

// Backend persistente principal.
//
// El plan original prevé RocksDB. Usar RocksDB desde Go exige cgo y la
// biblioteca C++ instalada en cada máquina, lo que complica la compilación
// cruzada, los binarios estáticos y la reproducibilidad. En su lugar se usa
// Pebble (github.com/cockroachdb/pebble), el motor de CockroachDB: un
// árbol LSM escrito en Go puro que reimplementa el diseño y el formato de
// SSTables de RocksDB (memtables, WAL, niveles, compactación por niveles,
// filtros Bloom, snapshots, lotes atómicos). Es el mismo motor que usa
// go-ethereum por defecto. El nombre del archivo se mantiene para respetar el
// plan; el tipo se llama PebbleDB para no inducir a error.

import (
	"bytes"
	"errors"
	"fmt"
	"sync"

	"github.com/cockroachdb/pebble"
	"github.com/cockroachdb/pebble/bloom"
)

// PebbleOptions configura la apertura de PebbleDB.
type PebbleOptions struct {
	// CacheMB es el tamaño de la caché de bloques en MiB.
	CacheMB int
	// Handles es el máximo de archivos abiertos.
	Handles int
	// ReadOnly abre sin permitir escrituras.
	ReadOnly bool
	// SyncWrites hace fsync del WAL en cada escritura (más lento, más seguro).
	// Si es false, una caída del SO puede perder las últimas escrituras, pero
	// nunca corrompe la base (el WAL de Pebble es consistente).
	SyncWrites bool
}

// PebbleDB es un KeyValueStore sobre Pebble.
type PebbleDB struct {
	db     *pebble.DB
	path   string
	wo     *pebble.WriteOptions
	mu     sync.RWMutex // protege closed frente a Close concurrente
	closed bool
}

// NewPebbleDB abre (o crea) una base Pebble en path.
func NewPebbleDB(path string, o PebbleOptions) (*PebbleDB, error) {
	if o.CacheMB < 16 {
		o.CacheMB = 16
	}
	if o.Handles < 16 {
		o.Handles = 16
	}
	cache := pebble.NewCache(int64(o.CacheMB) * 1024 * 1024)
	defer cache.Unref() // Open toma su propia referencia
	opts := &pebble.Options{
		Cache:        cache,
		MaxOpenFiles: o.Handles,
		ReadOnly:     o.ReadOnly,
		// Memtable de 1/4 de la caché (mín. 4 MiB): menos flushes pequeños.
		MemTableSize:                uint64(max(o.CacheMB/4, 4)) * 1024 * 1024,
		MemTableStopWritesThreshold: 2,
		MaxConcurrentCompactions:    func() int { return 2 },
	}
	// Filtro Bloom de 10 bits/clave en todos los niveles: las lecturas de
	// claves inexistentes (muy frecuentes en el trie) evitan tocar disco.
	opts.Levels = make([]pebble.LevelOptions, 7)
	for i := range opts.Levels {
		opts.Levels[i].FilterPolicy = bloom.FilterPolicy(10)
		opts.Levels[i].BlockSize = 4 * 1024
		opts.Levels[i].TargetFileSize = int64(2*1024*1024) << i
	}
	opts.EnsureDefaults()
	db, err := pebble.Open(path, opts)
	if err != nil {
		return nil, fmt.Errorf("storage: abriendo pebble en %s: %w", path, err)
	}
	wo := pebble.NoSync
	if o.SyncWrites {
		wo = pebble.Sync
	}
	return &PebbleDB{db: db, path: path, wo: wo}, nil
}

// Path devuelve el directorio de la base.
func (p *PebbleDB) Path() string { return p.path }

// check devuelve ErrClosed si la base está cerrada. Debe llamarse con mu.RLock.
func (p *PebbleDB) check() error {
	if p.closed {
		return ErrClosed
	}
	return nil
}

// Has implementa KeyValueReader.
func (p *PebbleDB) Has(key []byte) (bool, error) {
	_, err := p.Get(key)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

// Get implementa KeyValueReader. Pebble devuelve un slice que sólo es
// válido hasta cerrar el closer, por eso se copia.
func (p *PebbleDB) Get(key []byte) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if err := p.check(); err != nil {
		return nil, err
	}
	return pebbleGet(p.db.Get(key))
}

// pebbleGet normaliza el resultado de Get de Pebble (DB o Snapshot).
func pebbleGet(v []byte, closer interface{ Close() error }, err error) ([]byte, error) {
	if errors.Is(err, pebble.ErrNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	out := copyBytes(v)
	if out == nil {
		out = []byte{}
	}
	return out, closer.Close()
}

// Put implementa KeyValueWriter.
func (p *PebbleDB) Put(key, value []byte) error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if err := p.check(); err != nil {
		return err
	}
	return p.db.Set(key, value, p.wo)
}

// Delete implementa KeyValueWriter.
func (p *PebbleDB) Delete(key []byte) error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if err := p.check(); err != nil {
		return err
	}
	return p.db.Delete(key, p.wo)
}

// iterOptions construye los límites [prefix+start, UpperBound(prefix)).
func iterOptions(prefix, start []byte) *pebble.IterOptions {
	return &pebble.IterOptions{LowerBound: concat(prefix, start), UpperBound: UpperBound(prefix)}
}

// NewIterator implementa Iteratee.
func (p *PebbleDB) NewIterator(prefix, start []byte) Iterator {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if err := p.check(); err != nil {
		return &sliceIterator{err: err}
	}
	it, err := p.db.NewIter(iterOptions(prefix, start))
	if err != nil {
		return &sliceIterator{err: err}
	}
	return &pebbleIterator{it: it}
}

// pebbleIterator adapta pebble.Iterator a nuestra semántica "Next primero".
type pebbleIterator struct {
	it      *pebble.Iterator
	started bool
	err     error
}

// Next implementa Iterator.
func (i *pebbleIterator) Next() bool {
	if !i.started {
		i.started = true
		return i.it.First()
	}
	return i.it.Next()
}

// Key implementa Iterator.
func (i *pebbleIterator) Key() []byte {
	if !i.it.Valid() {
		return nil
	}
	return i.it.Key()
}

// Value implementa Iterator.
func (i *pebbleIterator) Value() []byte {
	if !i.it.Valid() {
		return nil
	}
	return i.it.Value()
}

// Error implementa Iterator.
func (i *pebbleIterator) Error() error {
	if i.err != nil {
		return i.err
	}
	return i.it.Error()
}

// Release implementa Iterator.
func (i *pebbleIterator) Release() {
	if i.it != nil {
		i.err = i.it.Close()
		i.it = nil
	}
}

// NewBatch implementa Batcher.
func (p *PebbleDB) NewBatch() Batch { return &pebbleBatch{db: p, b: p.db.NewBatch()} }

// pebbleBatch envuelve pebble.Batch.
type pebbleBatch struct {
	db   *PebbleDB
	b    *pebble.Batch
	size int
}

// Put implementa Batch (pebble copia los datos en su buffer).
func (b *pebbleBatch) Put(key, value []byte) error {
	b.size += len(key) + len(value)
	return b.b.Set(key, value, nil)
}

// Delete implementa Batch.
func (b *pebbleBatch) Delete(key []byte) error {
	b.size += len(key)
	return b.b.Delete(key, nil)
}

// ValueSize implementa Batch.
func (b *pebbleBatch) ValueSize() int { return b.size }

// Write implementa Batch: commit atómico.
func (b *pebbleBatch) Write() error {
	b.db.mu.RLock()
	defer b.db.mu.RUnlock()
	if err := b.db.check(); err != nil {
		return err
	}
	return b.b.Commit(b.db.wo)
}

// Reset implementa Batch.
func (b *pebbleBatch) Reset() { b.b.Reset(); b.size = 0 }

// Replay implementa Batch recorriendo la representación interna del lote.
func (b *pebbleBatch) Replay(w KeyValueWriter) error {
	r := b.b.Reader()
	for {
		kind, k, v, ok, err := r.Next()
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		switch kind {
		case pebble.InternalKeyKindSet:
			err = w.Put(k, v)
		case pebble.InternalKeyKindDelete:
			err = w.Delete(k)
		}
		if err != nil {
			return err
		}
	}
}

// NewSnapshot implementa Snapshotter con snapshots MVCC nativos de Pebble
// (O(1): sólo fijan un número de secuencia).
func (p *PebbleDB) NewSnapshot() (Snapshot, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if err := p.check(); err != nil {
		return nil, err
	}
	return &pebbleSnapshot{s: p.db.NewSnapshot()}, nil
}

// pebbleSnapshot envuelve pebble.Snapshot.
type pebbleSnapshot struct{ s *pebble.Snapshot }

// Has implementa Snapshot.
func (s *pebbleSnapshot) Has(key []byte) (bool, error) {
	_, err := s.Get(key)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

// Get implementa Snapshot.
func (s *pebbleSnapshot) Get(key []byte) ([]byte, error) { return pebbleGet(s.s.Get(key)) }

// NewIterator implementa Snapshot.
func (s *pebbleSnapshot) NewIterator(prefix, start []byte) Iterator {
	it, err := s.s.NewIter(iterOptions(prefix, start))
	if err != nil {
		return &sliceIterator{err: err}
	}
	return &pebbleIterator{it: it}
}

// Release implementa Snapshot.
func (s *pebbleSnapshot) Release() { _ = s.s.Close() }

// Compact implementa Compacter. Pebble exige start < end explícitos, así que
// los límites nil se traducen a la clave vacía y a "última clave + 0x00".
func (p *PebbleDB) Compact(start, limit []byte) error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if err := p.check(); err != nil {
		return err
	}
	if start == nil {
		start = []byte{}
	}
	if limit == nil {
		it, err := p.db.NewIter(&pebble.IterOptions{LowerBound: start})
		if err != nil {
			return err
		}
		if it.Last() {
			limit = append(copyBytes(it.Key()), 0)
		}
		if err := it.Close(); err != nil {
			return err
		}
		if limit == nil {
			return nil // base vacía
		}
	}
	if bytes.Compare(start, limit) >= 0 {
		return nil
	}
	return p.db.Compact(start, limit, true)
}

// Flush fuerza el volcado de la memtable a disco.
func (p *PebbleDB) Flush() error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if err := p.check(); err != nil {
		return err
	}
	return p.db.Flush()
}

// Stat implementa Stater con las métricas de Pebble (niveles, compactaciones, caché).
func (p *PebbleDB) Stat() (string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if err := p.check(); err != nil {
		return "", err
	}
	return p.db.Metrics().String(), nil
}

// DiskUsage devuelve el tamaño total aproximado en disco.
func (p *PebbleDB) DiskUsage() uint64 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return 0
	}
	return p.db.Metrics().DiskSpaceUsage()
}

// Close implementa io.Closer. Es idempotente.
func (p *PebbleDB) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	return p.db.Close()
}
