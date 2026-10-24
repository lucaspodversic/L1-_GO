package storage

// Checkpoints de finalidad.
//
// Cada vez que HotStuff finaliza un bloque frontera de época, el consenso
// guarda un Checkpoint con el certificado de quórum (QC) que lo prueba. Los
// checkpoints permiten: (1) arrancar un nodo nuevo desde un estado
// reciente confiando sólo en el conjunto de validadores (sincronización
// por checkpoint), (2) rechazar reorganizaciones por debajo de lo final y
// (3) decidir qué estados se pueden podar.
//
// Clave: "k" + número(8 bytes BE) → RLP(Checkpoint). El puntero
// "LastCheckpoint" guarda el número del más reciente.

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/l1/l1/types"
)

// ErrCheckpointNotFound indica que no existe el checkpoint pedido.
var ErrCheckpointNotFound = errors.New("storage: checkpoint no encontrado")

// Checkpoint es un bloque finalizado con su prueba de finalidad.
type Checkpoint struct {
	// Number y Hash identifican el bloque.
	Number uint64
	Hash   types.Hash
	// StateRoot es la raíz de estado tras el bloque.
	StateRoot types.Hash
	// Epoch y View son la época y la vista de consenso del QC.
	Epoch, View uint64
	// QC es el certificado de quórum serializado (lo interpreta consensus).
	QC []byte
}

// EncodeRLP serializa el checkpoint.
func (c *Checkpoint) EncodeRLP() []byte {
	return types.EncodeList(types.EncodeUint(c.Number), types.EncodeBytes(c.Hash[:]),
		types.EncodeBytes(c.StateRoot[:]), types.EncodeUint(c.Epoch), types.EncodeUint(c.View),
		types.EncodeBytes(c.QC))
}

// DecodeCheckpoint deserializa un checkpoint.
func DecodeCheckpoint(b []byte) (*Checkpoint, error) {
	it, err := types.DecodeRLP(b)
	if err != nil {
		return nil, err
	}
	f, err := it.ListN(6)
	if err != nil {
		return nil, fmt.Errorf("checkpoint: %w", err)
	}
	c := new(Checkpoint)
	if c.Number, err = f[0].Uint64(); err != nil {
		return nil, err
	}
	if c.Hash, err = f[1].Hash(); err != nil {
		return nil, err
	}
	if c.StateRoot, err = f[2].Hash(); err != nil {
		return nil, err
	}
	if c.Epoch, err = f[3].Uint64(); err != nil {
		return nil, err
	}
	if c.View, err = f[4].Uint64(); err != nil {
		return nil, err
	}
	if c.QC, err = f[5].BytesCopy(); err != nil {
		return nil, err
	}
	return c, nil
}

// checkpointKey es la clave de un checkpoint.
func checkpointKey(n uint64) []byte { return concat(checkpointPrefix, encodeNumber(n)) }

// WriteCheckpoint guarda un checkpoint y, si es el más alto, actualiza el
// puntero al último.
func WriteCheckpoint(db KeyValueStore, c *Checkpoint) error {
	b := db.NewBatch()
	if err := b.Put(checkpointKey(c.Number), c.EncodeRLP()); err != nil {
		return err
	}
	if last, ok := readLastCheckpointNumber(db); !ok || c.Number >= last {
		if err := b.Put(lastCheckpointKey, encodeNumber(c.Number)); err != nil {
			return err
		}
	}
	return b.Write()
}

// ReadCheckpoint lee el checkpoint del bloque n.
func ReadCheckpoint(r KeyValueReader, n uint64) (*Checkpoint, error) {
	b, err := r.Get(checkpointKey(n))
	if errors.Is(err, ErrNotFound) {
		return nil, ErrCheckpointNotFound
	}
	if err != nil {
		return nil, err
	}
	return DecodeCheckpoint(b)
}

// readLastCheckpointNumber lee el puntero al último checkpoint.
func readLastCheckpointNumber(r KeyValueReader) (uint64, bool) {
	b, err := r.Get(lastCheckpointKey)
	if err != nil || len(b) != 8 {
		return 0, false
	}
	return binary.BigEndian.Uint64(b), true
}

// ReadLatestCheckpoint devuelve el checkpoint más reciente.
func ReadLatestCheckpoint(r KeyValueReader) (*Checkpoint, error) {
	n, ok := readLastCheckpointNumber(r)
	if !ok {
		return nil, ErrCheckpointNotFound
	}
	return ReadCheckpoint(r, n)
}

// ListCheckpoints devuelve hasta limit checkpoints desde el bloque from
// (incluido), en orden ascendente.
func ListCheckpoints(db Iteratee, from uint64, limit int) ([]*Checkpoint, error) {
	it := db.NewIterator(checkpointPrefix, encodeNumber(from))
	defer it.Release()
	var out []*Checkpoint
	for (limit <= 0 || len(out) < limit) && it.Next() {
		c, err := DecodeCheckpoint(it.Value())
		if err != nil {
			return out, err
		}
		out = append(out, c)
	}
	return out, it.Error()
}

// PruneCheckpoints borra los checkpoints anteriores al bloque before
// (siempre conserva el último). Devuelve cuántos borró.
func PruneCheckpoints(db KeyValueStore, before uint64) (int, error) {
	last, _ := readLastCheckpointNumber(db)
	it := db.NewIterator(checkpointPrefix, nil)
	w := NewBatchWriter(db, 0)
	n := 0
	for it.Next() {
		k := it.Key()
		if len(k) != 9 {
			continue
		}
		num := binary.BigEndian.Uint64(k[1:])
		if num >= before || num == last {
			break // claves ordenadas: el resto es posterior
		}
		if err := w.Delete(copyBytes(k)); err != nil {
			it.Release()
			return n, err
		}
		n++
	}
	err := it.Error()
	it.Release()
	if err != nil {
		return n, err
	}
	return n, w.Flush()
}
