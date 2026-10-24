package storage

// Utilidades de prueba reutilizables por los tests de todos los paquetes.
//
// Este fichero NO termina en _test.go a propósito: así lo pueden importar
// los tests de vm/, chain/, consensus/... Para no arrastrar el paquete
// testing al binario del nodo, se define una interfaz TB mínima que
// *testing.T y *testing.B satisfacen.

import (
	"bytes"
	"errors"
	"fmt"
)

// TB es el subconjunto de testing.TB que se necesita.
type TB interface {
	Helper()
	Fatalf(format string, args ...any)
	Cleanup(func())
	TempDir() string
}

// NewTestDB devuelve una Database en memoria que se cierra al terminar.
func NewTestDB(t TB) *Database {
	t.Helper()
	db, err := Open(Config{Metrics: true}) // con métricas para poder inspeccionarlas
	if err != nil {
		t.Fatalf("NewTestDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// NewTestPebble devuelve un PebbleDB en un directorio temporal.
func NewTestPebble(t TB) *PebbleDB {
	t.Helper()
	db, err := NewPebbleDB(t.TempDir(), PebbleOptions{})
	if err != nil {
		t.Fatalf("NewTestPebble: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// TestKeyValueStore es una batería de conformidad: cualquier backend debe
// comportarse igual que MemoryDB. newDB debe devolver una base vacía.
func TestKeyValueStore(t TB, newDB func() KeyValueStore) {
	t.Helper()
	check := func(cond bool, format string, args ...any) {
		t.Helper()
		if !cond {
			t.Fatalf(format, args...)
		}
	}
	db := newDB()
	defer db.Close()

	// Put/Get/Has/Delete y ErrNotFound.
	_, err := db.Get([]byte("nada"))
	check(errors.Is(err, ErrNotFound), "Get de clave inexistente: %v", err)
	check(db.Put([]byte("a"), []byte("1")) == nil, "Put")
	v, err := db.Get([]byte("a"))
	check(err == nil && string(v) == "1", "Get a = %q, %v", v, err)
	has, _ := db.Has([]byte("a"))
	check(has, "Has a")
	check(db.Put([]byte("vacío"), []byte{}) == nil, "Put valor vacío")
	v, err = db.Get([]byte("vacío"))
	check(err == nil && len(v) == 0, "valor vacío: %q %v", v, err)
	check(db.Delete([]byte("a")) == nil, "Delete")
	has, _ = db.Has([]byte("a"))
	check(!has, "Has tras Delete")
	check(db.Delete([]byte("inexistente")) == nil, "Delete inexistente no es error")
	_ = db.Delete([]byte("vacío"))

	// Iteración ordenada, con prefijo y punto de inicio.
	keys := []string{"p1", "p3", "p2", "q1", "o9", "p"}
	for _, k := range keys {
		check(db.Put([]byte(k), []byte("v"+k)) == nil, "Put %s", k)
	}
	collect := func(prefix, start string) string {
		it := db.NewIterator([]byte(prefix), []byte(start))
		defer it.Release()
		var b bytes.Buffer
		for it.Next() {
			fmt.Fprintf(&b, "%s=%s,", it.Key(), it.Value())
		}
		check(it.Error() == nil, "iterador: %v", it.Error())
		return b.String()
	}
	check(collect("p", "") == "p=vp,p1=vp1,p2=vp2,p3=vp3,", "prefijo p: %s", collect("p", ""))
	check(collect("p", "2") == "p2=vp2,p3=vp3,", "prefijo p desde 2: %s", collect("p", "2"))
	check(collect("", "") == "o9=vo9,p=vp,p1=vp1,p2=vp2,p3=vp3,q1=vq1,", "todo: %s", collect("", ""))
	check(collect("z", "") == "", "prefijo vacío de resultados")

	// Lotes: atomicidad visible, Replay y Reset.
	b := db.NewBatch()
	_ = b.Put([]byte("b1"), []byte("x"))
	_ = b.Delete([]byte("p1"))
	check(b.ValueSize() > 0, "ValueSize")
	has, _ = db.Has([]byte("b1"))
	check(!has, "lote visible antes de Write")
	check(b.Write() == nil, "Write")
	has, _ = db.Has([]byte("b1"))
	check(has, "b1 tras Write")
	has, _ = db.Has([]byte("p1"))
	check(!has, "p1 borrado por el lote")
	mem := NewMemoryDB()
	check(b.Replay(mem) == nil, "Replay")
	has, _ = mem.Has([]byte("b1"))
	check(has, "Replay aplica Put")
	b.Reset()
	check(b.ValueSize() == 0, "Reset")

	// Snapshots: aislamiento respecto a escrituras posteriores.
	snap, err := db.NewSnapshot()
	check(err == nil, "NewSnapshot: %v", err)
	_ = db.Put([]byte("tras-snap"), []byte("1"))
	_ = db.Delete([]byte("p2"))
	has, _ = snap.Has([]byte("tras-snap"))
	check(!has, "snapshot ve escritura posterior")
	v, err = snap.Get([]byte("p2"))
	check(err == nil && string(v) == "vp2", "snapshot perdió p2: %q %v", v, err)
	snap.Release()

	// Compactación y estadísticas no deben fallar.
	check(db.Compact(nil, nil) == nil, "Compact")
	_, err = db.Stat()
	check(err == nil, "Stat: %v", err)
}
