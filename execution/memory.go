package execution

// Este archivo implementa la memoria lineal (volátil) de un marco de
// ejecución. La memoria se direcciona por bytes, crece en palabras de 32
// bytes y su expansión cuesta gas cuadrático (ver memoryGasCost en gas.go);
// el intérprete cobra ese gas ANTES de llamar a Resize, de modo que aquí no
// se hacen comprobaciones de límites costosas.

import "sync"

// Memory es la memoria de un marco de ejecución.
type Memory struct {
	store       []byte
	lastGasCost uint64 // coste total ya cobrado por la expansión actual
}

// memoryPool recicla memorias entre marcos.
var memoryPool = sync.Pool{New: func() any { return &Memory{} }}

// newMemory obtiene una memoria vacía del pool.
func newMemory() *Memory { return memoryPool.Get().(*Memory) }

// returnMemory devuelve la memoria al pool, descartando buffers enormes
// para no retener megas indefinidamente.
func returnMemory(m *Memory) {
	if cap(m.store) > 1<<20 {
		m.store = nil
	}
	m.store = m.store[:0]
	m.lastGasCost = 0
	memoryPool.Put(m)
}

// NewMemory crea una memoria vacía (API pública para pruebas).
func NewMemory() *Memory { return &Memory{} }

// Len devuelve el tamaño actual en bytes (siempre múltiplo de 32).
func (m *Memory) Len() int { return len(m.store) }

// Data devuelve el buffer subyacente (sin copiar).
func (m *Memory) Data() []byte { return m.store }

// Resize amplía la memoria hasta size bytes (rellenando con ceros). Nunca
// la reduce. El llamador debe haber redondeado size a múltiplo de 32.
func (m *Memory) Resize(size uint64) {
	if uint64(len(m.store)) >= size {
		return
	}
	if uint64(cap(m.store)) >= size {
		old := len(m.store)
		m.store = m.store[:size]
		clear(m.store[old:]) // el pool puede devolver basura previa
		return
	}
	n := make([]byte, size)
	copy(n, m.store)
	m.store = n
}

// Set copia value en [offset, offset+size). La memoria ya debe tener tamaño
// suficiente (garantizado por el cobro previo de expansión).
func (m *Memory) Set(offset, size uint64, value []byte) {
	if size == 0 {
		return
	}
	if offset+size > uint64(len(m.store)) {
		panic("execution: escritura de memoria fuera de rango (falta Resize)")
	}
	copy(m.store[offset:offset+size], value)
}

// Set32 escribe la palabra val (32 bytes big-endian) en offset.
func (m *Memory) Set32(offset uint64, val *Word) {
	if offset+32 > uint64(len(m.store)) {
		panic("execution: escritura de memoria fuera de rango (falta Resize)")
	}
	b := val.Bytes32()
	copy(m.store[offset:offset+32], b[:])
}

// SetByte escribe un único byte (MSTORE8).
func (m *Memory) SetByte(offset uint64, b byte) { m.store[offset] = b }

// GetCopy devuelve una copia de [offset, offset+size).
func (m *Memory) GetCopy(offset, size uint64) []byte {
	if size == 0 {
		return nil
	}
	out := make([]byte, size)
	copy(out, m.store[offset:offset+size])
	return out
}

// GetPtr devuelve una vista (sin copiar) de [offset, offset+size). El
// llamador no debe conservarla tras modificar la memoria.
func (m *Memory) GetPtr(offset, size uint64) []byte {
	if size == 0 {
		return nil
	}
	return m.store[offset : offset+size]
}

// Copy implementa MCOPY (EIP-5656): copia con solapamiento permitido.
func (m *Memory) Copy(dst, src, size uint64) {
	if size == 0 {
		return
	}
	copy(m.store[dst:dst+size], m.store[src:src+size]) // copy maneja solapes
}

// setPadded copia data[srcOff:srcOff+size] en memoria, rellenando con ceros
// lo que quede fuera de data. Es la semántica de CALLDATACOPY, CODECOPY y
// EXTCODECOPY.
func (m *Memory) setPadded(memOff uint64, data []byte, srcOff *Word, size uint64) {
	if size == 0 {
		return
	}
	dst := m.store[memOff : memOff+size]
	clear(dst)
	if !srcOff.IsUint64() || srcOff[0] >= uint64(len(data)) {
		return // todo el origen está fuera: sólo ceros
	}
	copy(dst, data[srcOff[0]:])
}
