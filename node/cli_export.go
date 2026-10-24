package node

// Subcomando export: vuelca génesis o cabecera actual.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/l1/l1/storage"
)

func cmdExport(args []string) error {
	cfg := DefaultConfig()
	fs := RegisterFlags("export", &cfg)
	var what string
	fs.StringVar(&what, "what", "genesis", "qué exportar: genesis|head")
	var out string
	fs.StringVar(&out, "out", "-", "fichero de salida (- = stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	db, err := storage.Open(storage.DefaultConfig(filepath.Join(cfg.DataDir, "chain")))
	if err != nil {
		return err
	}
	defer db.Close()
	var payload any
	switch what {
	case "genesis":
		g, err := storage.ReadGenesisSpec(db.KV)
		if err != nil {
			return err
		}
		if g == nil {
			return fmt.Errorf("no hay génesis en %s", cfg.DataDir)
		}
		payload = g
	case "head":
		h := db.Blocks.CurrentHeader()
		if h == nil {
			return fmt.Errorf("cadena vacía")
		}
		payload = h
	default:
		return fmt.Errorf("export: what desconocido %s", what)
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if out == "-" || out == "" {
		_, err = os.Stdout.Write(data)
		return err
	}
	return os.WriteFile(out, data, 0o644)
}
