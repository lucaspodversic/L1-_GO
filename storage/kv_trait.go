// Package storage implementa toda la persistencia del nodo:
//
//   - Abstracción clave/valor (este archivo) con dos backends: Pebble, un
//     motor LSM en Go puro compatible en diseño con RocksDB
//     (rocksdb_backend.go), y un backend en memoria para tests y nodos
//     efímeros (memory_backend.go). Lotes atómicos, snapshots de punto en el
//     tiempo, compactación, métricas y migraciones de esquema.
//   - Almacenes de la cadena: cabeceras, cuerpos, índice canónico, índice
//     de transacciones, recibos y checkpoints de finalidad BFT.
//   - Merkle Patricia Trie hexario compatible con Ethereum (trie_*.go),
//     con caché de nodos, pruebas de inclusión y pruning mark-and-sweep.
//   - StateDB: el estado mundial de cuentas sobre el trie, con journal
//     para revertir llamadas fallidas de la VM, snapshots anidados, access
//     lists EIP-2929, almacenamiento transitorio EIP-1153 y cálculo de la
//     raíz de estado.
//   - Write-Ahead Log segmentado (wal.go) para que el consenso persista
//     votos y propuestas antes de emitirlos (requisito de seguridad de
//     HotStuff tras un reinicio).
//
// Esquema de claves en disco (prefijos de 1 byte, números en big-endian de
// 8 bytes para que el orden lexicográfico coincida con el numérico):
//
//	"h" + num + hash  → cabecera RLP
//	"b" + num + hash  → cuerpo RLP (txs + QC)
//	"H" + hash        → número de bloque
//	"n" + num         → hash canónico
//	"l" + txHash      → entrada de índice de tx
//	"r" + num + hash  → recibos del bloque
//	"t" + hash        → nodo del trie
//	"c" + hash        → bytecode de contrato
//	"s" + hash        → preimagen de clave del trie seguro
//	"k" + num         → checkpoint finalizado
//	claves de texto   → metadatos (cabeza, finalizado, versión de esquema...)
package storage

import (
	"errors"
	"io"
)

// Errores comunes de la capa de almacenamiento.
var (
	// ErrNotFound indica que la clave no existe.
	ErrNotFound = errors.New("storage: no encontrado")
	// ErrClosed indica una operación sobre una base de datos cerrada.
	ErrClosed = errors.New("storage: base de datos cerrada")
	// ErrReadOnly indica una escritura sobre una base de datos de sólo lectura.
	ErrReadOnly = errors.New("storage: base de datos de sólo lectura")
)

// KeyValueReader lee claves.
type KeyValueReader interface {
	// Has informa si la clave existe.
	Has(key []byte) (bool, error)
	// Get devuelve una COPIA del valor, o ErrNotFound.
	Get(key []byte) ([]byte, error)
}

// KeyValueWriter escribe y borra claves.
type KeyValueWriter interface {
	// Put inserta o sobrescribe. La implementación no debe retener key ni
	// value tras volver (el llamador puede reutilizarlos).
	Put(key, value []byte) error
	// Delete borra la clave (no es error si no existe).
	Delete(key []byte) error
}

// Iterator recorre pares clave/valor en orden lexicográfico ascendente.
// Uso:
//
//	it := db.NewIterator(prefix, nil)
//	defer it.Release()
//	for it.Next() { k, v := it.Key(), it.Value() ... }
//	if err := it.Error(); err != nil { ... }
//
// Key y Value sólo son válidos hasta la siguiente llamada a Next: hay que
// copiarlos si se quieren conservar.
type Iterator interface {
	// Next avanza al siguiente par; devuelve false al agotarse o ante error.
	Next() bool
	// Key devuelve la clave actual.
	Key() []byte
	// Value devuelve el valor actual.
	Value() []byte
	// Error devuelve el error acumulado, si lo hubo.
	Error() error
	// Release libera los recursos del iterador. Es obligatorio llamarlo.
	Release()
}

// Iteratee crea iteradores.
type Iteratee interface {
	// NewIterator recorre las claves con el prefijo dado, empezando en
	// prefix+start (start es relativo al prefijo; ambos pueden ser nil).
	NewIterator(prefix, start []byte) Iterator
}

// Batch acumula escrituras en memoria y las aplica atómicamente con Write.
// No es seguro para uso concurrente.
type Batch interface {
	KeyValueWriter
	// ValueSize devuelve el volumen aproximado de datos acumulados.
	ValueSize() int
	// Write aplica todas las operaciones de forma atómica.
	Write() error
	// Reset vacía el lote para reutilizarlo.
	Reset()
	// Replay reaplica las operaciones sobre otro escritor (en orden).
	Replay(w KeyValueWriter) error
}

// Batcher crea lotes.
type Batcher interface {
	// NewBatch crea un lote vacío.
	NewBatch() Batch
}

// Snapshot es una vista inmutable de la base en un instante dado: las
// escrituras posteriores no son visibles a través de él.
type Snapshot interface {
	KeyValueReader
	Iteratee
	// Release libera el snapshot.
	Release()
}

// Snapshotter crea snapshots.
type Snapshotter interface {
	// NewSnapshot crea una vista de punto en el tiempo.
	NewSnapshot() (Snapshot, error)
}

// Compacter compacta rangos de claves para recuperar espacio.
type Compacter interface {
	// Compact compacta [start, limit); nil significa sin límite.
	Compact(start, limit []byte) error
}

// Stater expone estadísticas internas del motor.
type Stater interface {
	// Stat devuelve un texto legible con métricas del backend.
	Stat() (string, error)
}

// KeyValueStore es la interfaz completa que debe ofrecer un backend.
type KeyValueStore interface {
	KeyValueReader
	KeyValueWriter
	Iteratee
	Batcher
	Snapshotter
	Compacter
	Stater
	io.Closer
}

// UpperBound devuelve la menor clave mayor que todas las que empiezan con
// prefix (útil como límite superior exclusivo), o nil si no existe (prefijo
// vacío o todo 0xff).
func UpperBound(prefix []byte) []byte {
	for i := len(prefix) - 1; i >= 0; i-- {
		if prefix[i] != 0xff {
			out := append([]byte(nil), prefix[:i+1]...)
			out[i]++
			return out
		}
	}
	return nil
}

// copyBytes devuelve una copia de b (nil si b es nil).
func copyBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	return append(make([]byte, 0, len(b)), b...)
}

// concat concatena fragmentos en un slice nuevo.
func concat(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
