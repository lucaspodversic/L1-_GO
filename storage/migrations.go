package storage

// Migraciones del esquema de la base de datos.
//
// Cada cambio incompatible en el formato de claves/valores incrementa
// CurrentSchemaVersion y añade una Migration que transforma los datos de
// la versión anterior. Al abrir la base se ejecutan, en orden, las
// migraciones pendientes; nunca se permite abrir una base más nueva que el
// binario (degradar podría corromperla).

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"sort"
)

// CurrentSchemaVersion es la versión de esquema que escribe este binario.
const CurrentSchemaVersion uint64 = 1

// ErrSchemaDowngrade indica una base de una versión posterior.
var ErrSchemaDowngrade = errors.New("storage: la base de datos es de una versión más nueva")

// Migration lleva la base desde Version-1 hasta Version.
type Migration struct {
	// Version es la versión resultante.
	Version uint64
	// Name es una descripción breve para los logs.
	Name string
	// Apply transforma los datos. Debe ser idempotente: si el proceso muere
	// a mitad, se reejecutará entera.
	Apply func(db KeyValueStore) error
}

// Migrations es el registro de migraciones del binario. La versión 1 es el
// esquema inicial y no necesita ninguna.
var Migrations = []Migration{}

// ReadSchemaVersion devuelve la versión guardada (ok=false si no hay).
func ReadSchemaVersion(r KeyValueReader) (uint64, bool, error) {
	b, err := r.Get(schemaVersionKey)
	if errors.Is(err, ErrNotFound) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	if len(b) != 8 {
		return 0, false, fmt.Errorf("storage: versión de esquema corrupta")
	}
	return binary.BigEndian.Uint64(b), true, nil
}

// WriteSchemaVersion guarda la versión del esquema.
func WriteSchemaVersion(w KeyValueWriter, v uint64) error {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return w.Put(schemaVersionKey, b[:])
}

// isEmptyDB informa si la base no tiene ninguna clave.
func isEmptyDB(db KeyValueStore) (bool, error) {
	it := db.NewIterator(nil, nil)
	defer it.Release()
	has := it.Next()
	return !has, it.Error()
}

// RunMigrations aplica las migraciones pendientes hasta target.
//   - Base vacía: se marca directamente con target.
//   - Base con datos y sin versión: se considera versión 0 (pre-versionado).
func RunMigrations(db KeyValueStore, migs []Migration, target uint64) error {
	v, ok, err := ReadSchemaVersion(db)
	if err != nil {
		return err
	}
	if !ok {
		empty, err := isEmptyDB(db)
		if err != nil {
			return err
		}
		if empty {
			return WriteSchemaVersion(db, target)
		}
		v = 0
	}
	if v > target {
		return fmt.Errorf("%w (base v%d, binario v%d)", ErrSchemaDowngrade, v, target)
	}
	sorted := append([]Migration(nil), migs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Version < sorted[j].Version })
	for _, m := range sorted {
		if m.Version <= v || m.Version > target {
			continue
		}
		slog.Info("aplicando migración de base de datos", "versión", m.Version, "nombre", m.Name)
		if err := m.Apply(db); err != nil {
			return fmt.Errorf("migración %d (%s): %w", m.Version, m.Name, err)
		}
		// Se guarda la versión tras cada paso: si falla la siguiente no se
		// reejecutan las ya aplicadas.
		if err := WriteSchemaVersion(db, m.Version); err != nil {
			return err
		}
		v = m.Version
	}
	if v < target {
		return WriteSchemaVersion(db, target)
	}
	return nil
}
