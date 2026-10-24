package storage

// Exportación/importación de la base completa (o de un prefijo) como flujo
// binario. Sirve para copias de seguridad en caliente, para sembrar nodos
// nuevos sin sincronizar desde el génesis y para fixtures de tests.
//
// La exportación se hace sobre un Snapshot del backend, de modo que el nodo
// puede seguir escribiendo mientras tanto y el resultado es consistente.
//
// Formato:
//
//	magic    "L1SNAP01"                                  (8 bytes)
//	registro 0x01 | uvarint(len k) | k | uvarint(len v) | v   (repetido)
//	fin      0xFF                                         (1 byte)
//	trailer  count u64 BE | crc32c u32 BE   (CRC de todo lo anterior)
//
// El byte de tipo inicial de cada registro permite distinguir el fin del
// flujo de una clave vacía legítima.

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
)

// snapshotMagic identifica el formato y su versión.
const snapshotMagic = "L1SNAP01"

// Bytes de tipo de registro del flujo.
const (
	snapRecord byte = 0x01
	snapEnd    byte = 0xFF
)

// maxSnapshotField limita el tamaño de un campo al importar (defensa ante
// flujos corruptos que pidan reservar gigabytes).
const maxSnapshotField = 64 << 20

// crcTable es la tabla Castagnoli (CRC32C), acelerada por hardware en x86/ARM.
var crcTable = crc32.MakeTable(crc32.Castagnoli)

// ErrSnapshotCorrupt indica un flujo de snapshot inválido.
var ErrSnapshotCorrupt = errors.New("storage: snapshot corrupto")

// ExportSnapshot escribe en w todas las claves con el prefijo dado (nil =
// todas) y devuelve cuántas exportó.
func ExportSnapshot(db Snapshotter, prefix []byte, w io.Writer) (uint64, error) {
	snap, err := db.NewSnapshot()
	if err != nil {
		return 0, err
	}
	defer snap.Release()
	return ExportIterator(snap.NewIterator(prefix, nil), w)
}

// ExportIterator escribe el flujo a partir de un iterador (que libera).
func ExportIterator(it Iterator, w io.Writer) (uint64, error) {
	defer it.Release()
	crc := crc32.New(crcTable)
	bw := bufio.NewWriterSize(io.MultiWriter(w, crc), 1<<16)
	if _, err := bw.WriteString(snapshotMagic); err != nil {
		return 0, err
	}
	var count uint64
	var tmp [binary.MaxVarintLen64]byte
	for it.Next() {
		k, v := it.Key(), it.Value()
		bw.WriteByte(snapRecord)
		bw.Write(tmp[:binary.PutUvarint(tmp[:], uint64(len(k)))])
		bw.Write(k)
		bw.Write(tmp[:binary.PutUvarint(tmp[:], uint64(len(v)))])
		if _, err := bw.Write(v); err != nil {
			return count, err
		}
		count++
	}
	if err := it.Error(); err != nil {
		return count, err
	}
	bw.WriteByte(snapEnd)
	if err := bw.Flush(); err != nil {
		return count, err
	}
	// El trailer no entra en el CRC (se escribe directamente en w).
	var trailer [12]byte
	binary.BigEndian.PutUint64(trailer[:8], count)
	binary.BigEndian.PutUint32(trailer[8:], crc.Sum32())
	_, err := w.Write(trailer[:])
	return count, err
}

// crcReader calcula el CRC de todo lo que se lee a través de él.
type crcReader struct {
	r   *bufio.Reader
	crc hash.Hash32
}

// ReadByte lee un byte actualizando el CRC (necesario para ReadUvarint).
func (c *crcReader) ReadByte() (byte, error) {
	b, err := c.r.ReadByte()
	if err == nil {
		c.crc.Write([]byte{b})
	}
	return b, err
}

// Read lee actualizando el CRC.
func (c *crcReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.crc.Write(p[:n])
	return n, err
}

// readField lee un campo uvarint(len) + bytes.
func (c *crcReader) readField() ([]byte, error) {
	n, err := binary.ReadUvarint(c)
	if err != nil {
		return nil, err
	}
	if n > maxSnapshotField {
		return nil, fmt.Errorf("%w: campo de %d bytes", ErrSnapshotCorrupt, n)
	}
	b := make([]byte, n)
	_, err = io.ReadFull(c, b)
	return b, err
}

// ImportSnapshot lee un flujo de ExportSnapshot y escribe sus pares en db
// mediante lotes. Verifica el número de registros y el CRC; si fallan, los
// datos ya escritos quedan en la base (el llamador debería importar sobre
// una base vacía y descartarla ante error).
func ImportSnapshot(db Batcher, r io.Reader) (uint64, error) {
	cr := &crcReader{r: bufio.NewReaderSize(r, 1<<16), crc: crc32.New(crcTable)}
	magic := make([]byte, len(snapshotMagic))
	if _, err := io.ReadFull(cr, magic); err != nil || string(magic) != snapshotMagic {
		return 0, fmt.Errorf("%w: cabecera inválida", ErrSnapshotCorrupt)
	}
	bw := NewBatchWriter(db, 0)
	var count uint64
	for {
		t, err := cr.ReadByte()
		if err != nil {
			return count, fmt.Errorf("%w: %v", ErrSnapshotCorrupt, err)
		}
		if t == snapEnd {
			break
		}
		if t != snapRecord {
			return count, fmt.Errorf("%w: tipo de registro %#x", ErrSnapshotCorrupt, t)
		}
		k, err := cr.readField()
		if err != nil {
			return count, fmt.Errorf("%w: %v", ErrSnapshotCorrupt, err)
		}
		v, err := cr.readField()
		if err != nil {
			return count, fmt.Errorf("%w: %v", ErrSnapshotCorrupt, err)
		}
		if err := bw.Put(k, v); err != nil {
			return count, err
		}
		count++
	}
	sum := cr.crc.Sum32()
	var trailer [12]byte
	if _, err := io.ReadFull(cr.r, trailer[:]); err != nil {
		return count, fmt.Errorf("%w: trailer truncado", ErrSnapshotCorrupt)
	}
	if binary.BigEndian.Uint64(trailer[:8]) != count {
		return count, fmt.Errorf("%w: número de registros no coincide", ErrSnapshotCorrupt)
	}
	if binary.BigEndian.Uint32(trailer[8:]) != sum {
		return count, fmt.Errorf("%w: CRC no coincide", ErrSnapshotCorrupt)
	}
	return count, bw.Flush()
}
