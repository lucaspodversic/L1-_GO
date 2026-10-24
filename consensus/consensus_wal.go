package consensus

// WAL de consenso: persiste el RoundSnapshot antes de emitir un voto o
// timeout. Si el nodo se reinicia, Restore evita que se vuelva a votar en
// la misma vista (equivocación).

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/l1/l1/storage"
)

// ErrWALMissing indica que no hay ninguna entrada en el WAL.
var ErrWALMissing = errors.New("consenso: wal vacío")

// ConsensusWAL envuelve storage.WAL con codificación del RoundSnapshot.
type ConsensusWAL struct {
	wal *storage.WAL
}

// OpenConsensusWAL abre (o crea) el WAL de consenso en dir.
func OpenConsensusWAL(dir string) (*ConsensusWAL, error) {
	w, err := storage.OpenWAL(dir, storage.WALOptions{Sync: true})
	if err != nil {
		return nil, err
	}
	return &ConsensusWAL{wal: w}, nil
}

// Close cierra el fichero subyacente.
func (w *ConsensusWAL) Close() error {
	if w == nil || w.wal == nil {
		return nil
	}
	return w.wal.Close()
}

// encodeSnapshot serializa RoundSnapshot como 4×u64 little-endian.
func encodeSnapshot(s RoundSnapshot) []byte {
	b := make([]byte, 32)
	binary.LittleEndian.PutUint64(b[0:], s.Epoch)
	binary.LittleEndian.PutUint64(b[8:], s.View)
	binary.LittleEndian.PutUint64(b[16:], s.LastVotedView)
	binary.LittleEndian.PutUint64(b[24:], s.HighQCView)
	return b
}

// decodeSnapshot es la inversa.
func decodeSnapshot(b []byte) (RoundSnapshot, error) {
	if len(b) < 32 {
		return RoundSnapshot{}, fmt.Errorf("consenso: snapshot wal de %d bytes", len(b))
	}
	return RoundSnapshot{
		Epoch:         binary.LittleEndian.Uint64(b[0:]),
		View:          binary.LittleEndian.Uint64(b[8:]),
		LastVotedView: binary.LittleEndian.Uint64(b[16:]),
		HighQCView:    binary.LittleEndian.Uint64(b[24:]),
	}, nil
}

// Persist escribe el snapshot actual y hace fsync.
func (w *ConsensusWAL) Persist(s RoundSnapshot) error {
	_, err := w.wal.Write(encodeSnapshot(s))
	if err != nil {
		return err
	}
	return w.wal.Sync()
}

// LoadLast recupera el último snapshot persistido.
func (w *ConsensusWAL) LoadLast() (RoundSnapshot, error) {
	last := w.wal.LastIndex()
	if last == 0 {
		return RoundSnapshot{}, ErrWALMissing
	}
	var snap RoundSnapshot
	err := w.wal.Replay(last, func(_ uint64, data []byte) error {
		var e error
		snap, e = decodeSnapshot(data)
		return e
	})
	return snap, err
}
