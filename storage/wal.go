package storage

// WAL (write-ahead log) genérico basado en segmentos.
//
// El consenso HotStuff debe recordar, ANTES de enviar un voto, qué ha
// votado y su bloque bloqueado (locked QC): si el nodo se reinicia y
// olvida, podría votar dos veces en la misma vista (equivocación, que
// rompe la seguridad y se penaliza). El WAL da esa durabilidad: cada
// registro se añade al final de un fichero y, con Sync, se hace fsync antes
// de devolver.
//
// Formato de cada trama (little-endian):
//
//	longitud u32 | crc32c u32 | índice u64 | carga útil
//
// El CRC cubre índice+carga. Los registros tienen índices consecutivos
// desde 1. Los ficheros se llaman "%016d.wal" con el índice del primer
// registro que contienen y se rotan al superar SegmentSize.
//
// Recuperación: si el proceso muere a mitad de una escritura, la cola del
// último segmento puede quedar "rasgada" (trama incompleta o CRC erróneo).
// Al abrir, se trunca el último segmento en la primera trama inválida; una
// trama inválida en un segmento que no es el último es corrupción real.

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// ErrWALCorrupt indica corrupción en un segmento no final.
var ErrWALCorrupt = errors.New("wal: segmento corrupto")

// ErrWALClosed indica uso tras Close.
var ErrWALClosed = errors.New("wal: cerrado")

// walHeaderSize es el tamaño de la cabecera de trama.
const walHeaderSize = 4 + 4 + 8

// walMaxRecord limita el tamaño de un registro (protege de longitudes
// basura en tramas corruptas).
const walMaxRecord = 64 << 20

// La tabla CRC32-Castagnoli (crcTable) se comparte con snapshot.go.

// WALOptions configura el WAL.
type WALOptions struct {
	// SegmentSize es el tamaño a partir del cual se rota (por defecto 64 MiB).
	SegmentSize int64
	// Sync hace fsync tras cada Write.
	Sync bool
}

// WAL es un registro de escritura anticipada.
type WAL struct {
	mu       sync.Mutex
	dir      string
	opts     WALOptions
	segments []uint64 // índice inicial de cada segmento, ascendente
	f        *os.File // segmento activo (el último)
	segSize  int64
	next     uint64 // índice del próximo registro
	closed   bool
}

// segmentName devuelve el nombre de fichero de un segmento.
func segmentName(start uint64) string { return fmt.Sprintf("%016d.wal", start) }

// OpenWAL abre (o crea) un WAL en dir, recuperando una cola rasgada.
func OpenWAL(dir string, opts WALOptions) (*WAL, error) {
	if opts.SegmentSize <= 0 {
		opts.SegmentSize = 64 << 20
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	w := &WAL{dir: dir, opts: opts, next: 1}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		var start uint64
		if !strings.HasSuffix(e.Name(), ".wal") {
			continue
		}
		if _, err := fmt.Sscanf(e.Name(), "%016d.wal", &start); err == nil {
			w.segments = append(w.segments, start)
		}
	}
	sort.Slice(w.segments, func(i, j int) bool { return w.segments[i] < w.segments[j] })
	if len(w.segments) == 0 {
		if err := w.openSegment(1); err != nil {
			return nil, err
		}
		return w, nil
	}
	// Escanea el último segmento para hallar el final válido.
	last := w.segments[len(w.segments)-1]
	path := filepath.Join(dir, segmentName(last))
	count, validLen, err := scanSegment(path, last, nil)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}
	if st, err := f.Stat(); err == nil && st.Size() > validLen {
		// Cola rasgada: se descarta.
		if err := f.Truncate(validLen); err != nil {
			f.Close()
			return nil, err
		}
	}
	if _, err := f.Seek(validLen, io.SeekStart); err != nil {
		f.Close()
		return nil, err
	}
	w.f, w.segSize, w.next = f, validLen, last+count
	return w, nil
}

// scanSegment lee las tramas válidas de un segmento llamando a fn por cada
// una. Devuelve cuántas leyó y el desplazamiento del final válido. Una
// trama inválida detiene el escaneo (sin error: lo decide el llamador).
func scanSegment(path string, start uint64, fn func(idx uint64, data []byte) error) (uint64, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 1<<16)
	var (
		count uint64
		off   int64
		hdr   [walHeaderSize]byte
	)
	for {
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return count, off, nil // EOF o cabecera incompleta
		}
		n := binary.LittleEndian.Uint32(hdr[0:4])
		sum := binary.LittleEndian.Uint32(hdr[4:8])
		idx := binary.LittleEndian.Uint64(hdr[8:16])
		if n > walMaxRecord || idx != start+count {
			return count, off, nil
		}
		data := make([]byte, n)
		if _, err := io.ReadFull(r, data); err != nil {
			return count, off, nil
		}
		crc := crc32.Update(crc32.Checksum(hdr[8:16], crcTable), crcTable, data)
		if crc != sum {
			return count, off, nil
		}
		if fn != nil {
			if err := fn(idx, data); err != nil {
				return count, off, err
			}
		}
		count++
		off += int64(walHeaderSize) + int64(n)
	}
}

// openSegment crea un segmento nuevo que empieza en start y lo activa.
func (w *WAL) openSegment(start uint64) error {
	f, err := os.OpenFile(filepath.Join(w.dir, segmentName(start)), os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if w.f != nil {
		if err := w.f.Sync(); err != nil {
			f.Close()
			return err
		}
		w.f.Close()
	}
	w.f, w.segSize = f, 0
	w.segments = append(w.segments, start)
	return syncDir(w.dir)
}

// syncDir hace fsync del directorio para que la creación del fichero sea
// duradera (en Linux un fichero nuevo puede perderse sin esto).
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	_ = d.Sync() // algunos sistemas de ficheros no lo soportan
	return nil
}

// Write añade un registro y devuelve su índice.
func (w *WAL) Write(data []byte) (uint64, error) {
	if len(data) > walMaxRecord {
		return 0, fmt.Errorf("wal: registro demasiado grande (%d bytes)", len(data))
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, ErrWALClosed
	}
	frame := int64(walHeaderSize + len(data))
	if w.segSize > 0 && w.segSize+frame > w.opts.SegmentSize {
		if err := w.openSegment(w.next); err != nil {
			return 0, err
		}
	}
	buf := make([]byte, walHeaderSize+len(data))
	binary.LittleEndian.PutUint32(buf[0:4], uint32(len(data)))
	binary.LittleEndian.PutUint64(buf[8:16], w.next)
	copy(buf[walHeaderSize:], data)
	binary.LittleEndian.PutUint32(buf[4:8], crc32.Checksum(buf[8:], crcTable))
	if _, err := w.f.Write(buf); err != nil {
		return 0, err
	}
	if w.opts.Sync {
		if err := w.f.Sync(); err != nil {
			return 0, err
		}
	}
	w.segSize += frame
	idx := w.next
	w.next++
	return idx, nil
}

// Sync fuerza a disco lo escrito.
func (w *WAL) Sync() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return ErrWALClosed
	}
	return w.f.Sync()
}

// FirstIndex devuelve el índice del primer registro conservado.
func (w *WAL) FirstIndex() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.segments[0]
}

// LastIndex devuelve el índice del último registro (0 si no hay).
func (w *WAL) LastIndex() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.next - 1
}

// Replay llama a fn con cada registro de índice >= from, en orden.
func (w *WAL) Replay(from uint64, fn func(index uint64, data []byte) error) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return ErrWALClosed
	}
	if !w.opts.Sync {
		_ = w.f.Sync() // lo escrito por esta instancia debe ser legible
	}
	for i, start := range w.segments {
		end := w.next // índice siguiente al último del segmento
		if i+1 < len(w.segments) {
			end = w.segments[i+1]
		}
		if end <= from {
			continue // segmento entero anterior a from
		}
		count, _, err := scanSegment(filepath.Join(w.dir, segmentName(start)), start, func(idx uint64, d []byte) error {
			if idx < from {
				return nil
			}
			return fn(idx, d)
		})
		if err != nil {
			return err
		}
		if start+count != end {
			return fmt.Errorf("%w: %s (leídos %d de %d)", ErrWALCorrupt, segmentName(start), count, end-start)
		}
	}
	return nil
}

// TruncateBefore borra los segmentos cuyos registros son todos anteriores
// a index (el segmento activo nunca se borra). Devuelve cuántos borró.
func (w *WAL) TruncateBefore(index uint64) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, ErrWALClosed
	}
	removed := 0
	for len(w.segments) > 1 && w.segments[1] <= index {
		if err := os.Remove(filepath.Join(w.dir, segmentName(w.segments[0]))); err != nil {
			return removed, err
		}
		w.segments = w.segments[1:]
		removed++
	}
	return removed, nil
}

// Close sincroniza y cierra el segmento activo.
func (w *WAL) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	err := w.f.Sync()
	if cerr := w.f.Close(); err == nil {
		err = cerr
	}
	return err
}
