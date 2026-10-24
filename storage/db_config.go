package storage

// Configuración y apertura de la base de datos completa del nodo.
//
// Open es el único punto de entrada que usan node/ y cmd/: elige backend
// (memoria o Pebble), aplica métricas, ejecuta migraciones y construye las
// capas superiores (nodos del trie, estado, bloques, compactador).

import (
	"errors"
	"os"
	"path/filepath"
	"time"
)

// Config configura la base de datos.
type Config struct {
	// DataDir es el directorio de datos; vacío = base en memoria.
	DataDir string `json:"dataDir"`
	// CacheMB es la caché de bloques de Pebble en MiB.
	CacheMB int `json:"cacheMB"`
	// Handles es el máximo de ficheros abiertos.
	Handles int `json:"handles"`
	// ReadOnly abre la base sin permitir escrituras.
	ReadOnly bool `json:"readOnly"`
	// SyncWrites hace fsync en cada lote (más lento, más seguro).
	SyncWrites bool `json:"syncWrites"`
	// TrieCacheMB es la caché de nodos del trie limpios en MiB.
	TrieCacheMB int `json:"trieCacheMB"`
	// BlockCache es el número de cabeceras/cuerpos en caché.
	BlockCache int `json:"blockCache"`
	// CompactionInterval es el periodo de compactación (0 = desactivada).
	CompactionInterval time.Duration `json:"compactionInterval"`
	// Metrics envuelve el backend en un MeteredDB.
	Metrics bool `json:"metrics"`
}

// DefaultConfig devuelve valores razonables para un nodo validador.
func DefaultConfig(dataDir string) Config {
	return Config{
		DataDir: dataDir, CacheMB: 512, Handles: 1024, TrieCacheMB: 256,
		BlockCache: 256, CompactionInterval: 6 * time.Hour, Metrics: true,
	}
}

// Database agrupa todas las capas de almacenamiento.
type Database struct {
	// KV es el almacén clave-valor (posiblemente con métricas).
	KV KeyValueStore
	// Nodes es la base de nodos del trie.
	Nodes *NodeDatabase
	// State es la base de estado para crear StateDB.
	State *StateDatabase
	// Blocks es el almacén de bloques, recibos e índices.
	Blocks *BlockStore
	// Compactor es el compactador en segundo plano.
	Compactor *Compactor
	// Metered es el envoltorio de métricas (nil si desactivado).
	Metered *MeteredDB
	// Config es la configuración usada.
	Config Config
}

// chainDataDir es el subdirectorio de Pebble dentro de DataDir.
const chainDataDir = "chaindata"

// Open abre (o crea) la base de datos según cfg.
func Open(cfg Config) (*Database, error) {
	var kv KeyValueStore
	if cfg.DataDir == "" {
		kv = NewMemoryDB()
	} else {
		if !cfg.ReadOnly {
			if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
				return nil, err
			}
		}
		p, err := NewPebbleDB(filepath.Join(cfg.DataDir, chainDataDir), PebbleOptions{
			CacheMB: cfg.CacheMB, Handles: cfg.Handles, ReadOnly: cfg.ReadOnly, SyncWrites: cfg.SyncWrites,
		})
		if err != nil {
			return nil, err
		}
		kv = p
	}
	d := &Database{Config: cfg}
	if cfg.Metrics {
		d.Metered = NewMeteredDB(kv)
		kv = d.Metered
	}
	if !cfg.ReadOnly {
		if err := RunMigrations(kv, Migrations, CurrentSchemaVersion); err != nil {
			kv.Close()
			return nil, err
		}
	} else if v, ok, err := ReadSchemaVersion(kv); err != nil || (ok && v > CurrentSchemaVersion) {
		kv.Close()
		if err == nil {
			err = ErrSchemaDowngrade
		}
		return nil, err
	}
	d.KV = kv
	d.Nodes = NewNodeDatabase(kv, cfg.TrieCacheMB)
	d.State = NewStateDatabase(d.Nodes)
	if cfg.BlockCache <= 0 {
		cfg.BlockCache = 256
	}
	d.Blocks = NewBlockStore(kv, cfg.BlockCache)
	d.Compactor = NewCompactor(kv, cfg.CompactionInterval, nil)
	if !cfg.ReadOnly {
		d.Compactor.Start()
	}
	return d, nil
}

// Close detiene el compactador, vuelca los nodos pendientes y cierra.
func (d *Database) Close() error {
	d.Compactor.Stop()
	var errs []error
	if !d.Config.ReadOnly {
		errs = append(errs, d.Nodes.Flush())
	}
	errs = append(errs, d.KV.Close())
	return errors.Join(errs...)
}
