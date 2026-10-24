package storage

// Escritura por lotes.
//
//   - opBatch: lote genérico que registra operaciones en orden y las aplica
//     con una función de "commit" del backend (lo usa MemoryDB).
//   - BatchWriter: envoltorio que vacía automáticamente el lote cuando supera
//     un umbral, para importar grandes volúmenes (génesis grandes, sync de
//     estado, pruning) sin acumular cientos de MiB en memoria.

// IdealBatchSize es el volumen a partir del cual conviene escribir un lote:
// suficientemente grande para amortizar el coste de la escritura atómica y
// suficientemente pequeño para no penalizar la memoria ni la latencia.
const IdealBatchSize = 100 * 1024

// batchOp es una operación registrada en un lote.
type batchOp struct {
	key, value []byte
	delete     bool
}

// opBatch es un Batch que registra operaciones y las aplica con commit.
type opBatch struct {
	ops    []batchOp
	size   int
	commit func([]batchOp) error
}

// newOpBatch crea un lote que se aplicará con commit.
func newOpBatch(commit func([]batchOp) error) *opBatch { return &opBatch{commit: commit} }

// Put implementa Batch (copia key y value).
func (b *opBatch) Put(key, value []byte) error {
	b.ops = append(b.ops, batchOp{key: copyBytes(key), value: copyBytes(value)})
	b.size += len(key) + len(value)
	return nil
}

// Delete implementa Batch.
func (b *opBatch) Delete(key []byte) error {
	b.ops = append(b.ops, batchOp{key: copyBytes(key), delete: true})
	b.size += len(key)
	return nil
}

// ValueSize implementa Batch.
func (b *opBatch) ValueSize() int { return b.size }

// Write implementa Batch.
func (b *opBatch) Write() error { return b.commit(b.ops) }

// Reset implementa Batch.
func (b *opBatch) Reset() { b.ops, b.size = b.ops[:0], 0 }

// Replay implementa Batch.
func (b *opBatch) Replay(w KeyValueWriter) error {
	for _, op := range b.ops {
		var err error
		if op.delete {
			err = w.Delete(op.key)
		} else {
			err = w.Put(op.key, op.value)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// BatchWriter es un KeyValueWriter que acumula en un Batch y lo escribe
// cada vez que supera Threshold bytes. Atención: la atomicidad sólo se
// garantiza dentro de cada vaciado, no para el conjunto completo.
type BatchWriter struct {
	db        Batcher
	batch     Batch
	threshold int
	// Flushes cuenta cuántos lotes se han escrito.
	Flushes int
	// Ops cuenta las operaciones totales recibidas.
	Ops int
}

// NewBatchWriter crea un escritor con el umbral dado (IdealBatchSize si ≤0).
func NewBatchWriter(db Batcher, threshold int) *BatchWriter {
	if threshold <= 0 {
		threshold = IdealBatchSize
	}
	return &BatchWriter{db: db, batch: db.NewBatch(), threshold: threshold}
}

// Put implementa KeyValueWriter.
func (w *BatchWriter) Put(key, value []byte) error {
	if err := w.batch.Put(key, value); err != nil {
		return err
	}
	w.Ops++
	return w.maybeFlush()
}

// Delete implementa KeyValueWriter.
func (w *BatchWriter) Delete(key []byte) error {
	if err := w.batch.Delete(key); err != nil {
		return err
	}
	w.Ops++
	return w.maybeFlush()
}

// maybeFlush escribe el lote si superó el umbral.
func (w *BatchWriter) maybeFlush() error {
	if w.batch.ValueSize() >= w.threshold {
		return w.Flush()
	}
	return nil
}

// Flush escribe lo pendiente (si hay algo) y reinicia el lote.
func (w *BatchWriter) Flush() error {
	if w.batch.ValueSize() == 0 {
		return nil
	}
	if err := w.batch.Write(); err != nil {
		return err
	}
	w.Flushes++
	w.batch.Reset()
	return nil
}
