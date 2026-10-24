package storage

// MeteredDB: envoltorio de KeyValueStore que cuenta operaciones y bytes.
// Los contadores son atómicos (sin cerrojos en la ruta caliente) y se
// exponen con Stats() para el endpoint de métricas del nodo.

import (
	"fmt"
	"sync/atomic"
	"time"
)

// MeteredStats es una instantánea de los contadores.
type MeteredStats struct {
	Reads, ReadBytes, Misses   uint64
	Writes, WriteBytes         uint64
	Deletes, Batches, BatchOps uint64
	Iterators                  uint64
	// ReadTime es el tiempo acumulado en Get.
	ReadTime time.Duration
}

// MeteredDB cuenta operaciones sobre otra base.
type MeteredDB struct {
	KeyValueStore
	reads, readBytes, misses atomic.Uint64
	writes, writeBytes       atomic.Uint64
	deletes, batches, ops    atomic.Uint64
	iterators                atomic.Uint64
	readNanos                atomic.Int64
}

// NewMeteredDB envuelve db.
func NewMeteredDB(db KeyValueStore) *MeteredDB { return &MeteredDB{KeyValueStore: db} }

// Get cuenta la lectura y su duración.
func (m *MeteredDB) Get(key []byte) ([]byte, error) {
	start := time.Now()
	v, err := m.KeyValueStore.Get(key)
	m.readNanos.Add(int64(time.Since(start)))
	m.reads.Add(1)
	if err != nil {
		m.misses.Add(1)
	} else {
		m.readBytes.Add(uint64(len(v)))
	}
	return v, err
}

// Put cuenta la escritura.
func (m *MeteredDB) Put(key, value []byte) error {
	m.writes.Add(1)
	m.writeBytes.Add(uint64(len(key) + len(value)))
	return m.KeyValueStore.Put(key, value)
}

// Delete cuenta el borrado.
func (m *MeteredDB) Delete(key []byte) error {
	m.deletes.Add(1)
	return m.KeyValueStore.Delete(key)
}

// NewIterator cuenta los iteradores creados.
func (m *MeteredDB) NewIterator(prefix, start []byte) Iterator {
	m.iterators.Add(1)
	return m.KeyValueStore.NewIterator(prefix, start)
}

// NewBatch devuelve un lote que cuenta al escribirse.
func (m *MeteredDB) NewBatch() Batch { return &meteredBatch{Batch: m.KeyValueStore.NewBatch(), m: m} }

// meteredBatch cuenta operaciones de un lote.
type meteredBatch struct {
	Batch
	m   *MeteredDB
	ops uint64
}

// Put cuenta la operación.
func (b *meteredBatch) Put(k, v []byte) error { b.ops++; return b.Batch.Put(k, v) }

// Delete cuenta la operación.
func (b *meteredBatch) Delete(k []byte) error { b.ops++; return b.Batch.Delete(k) }

// Write registra el lote al confirmarlo.
func (b *meteredBatch) Write() error {
	b.m.batches.Add(1)
	b.m.ops.Add(b.ops)
	b.m.writeBytes.Add(uint64(b.ValueSize()))
	return b.Batch.Write()
}

// Reset reinicia el contador local.
func (b *meteredBatch) Reset() { b.ops = 0; b.Batch.Reset() }

// Stats devuelve una instantánea de los contadores.
func (m *MeteredDB) Stats() MeteredStats {
	return MeteredStats{
		Reads: m.reads.Load(), ReadBytes: m.readBytes.Load(), Misses: m.misses.Load(),
		Writes: m.writes.Load(), WriteBytes: m.writeBytes.Load(),
		Deletes: m.deletes.Load(), Batches: m.batches.Load(), BatchOps: m.ops.Load(),
		Iterators: m.iterators.Load(), ReadTime: time.Duration(m.readNanos.Load()),
	}
}

// Stat añade los contadores al informe del backend.
func (m *MeteredDB) Stat() (string, error) {
	inner, err := m.KeyValueStore.Stat()
	s := m.Stats()
	return fmt.Sprintf("lecturas=%d (fallos=%d, %dB, %s) escrituras=%d (%dB) borrados=%d lotes=%d/%d ops iteradores=%d\n%s",
		s.Reads, s.Misses, s.ReadBytes, s.ReadTime, s.Writes, s.WriteBytes, s.Deletes, s.Batches, s.BatchOps, s.Iterators, inner), err
}
