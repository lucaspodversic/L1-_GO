package node

// Carga de configuración desde JSON y flags.

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

// LoadConfigFile lee un JSON de configuración.
func LoadConfigFile(path string) (Config, error) {
	cfg := DefaultConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("node: config: %w", err)
	}
	return cfg, nil
}

// SaveConfigFile escribe la config.
func SaveConfigFile(path string, cfg Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// RegisterFlags registra flags sobre cfg y devuelve el FlagSet.
func RegisterFlags(name string, cfg *Config) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.StringVar(&cfg.DataDir, "datadir", cfg.DataDir, "directorio de datos")
	fs.StringVar(&cfg.ListenAddr, "listen", cfg.ListenAddr, "dirección P2P")
	fs.StringVar(&cfg.RPCAddr, "rpc", cfg.RPCAddr, "dirección JSON-RPC HTTP")
	fs.StringVar(&cfg.RPCWSAddr, "ws", cfg.RPCWSAddr, "dirección JSON-RPC WebSocket")
	fs.StringVar(&cfg.Bootnodes, "bootnodes", cfg.Bootnodes, "bootnodes separados por comas")
	fs.StringVar(&cfg.ValidatorKey, "validator-key", cfg.ValidatorKey, "ruta clave validador")
	fs.StringVar(&cfg.NodeKey, "node-key", cfg.NodeKey, "ruta clave nodo P2P")
	fs.StringVar(&cfg.GenesisFile, "genesis", cfg.GenesisFile, "ruta genesis.json")
	fs.StringVar(&cfg.LogLevel, "log", cfg.LogLevel, "nivel de log")
	fs.BoolVar(&cfg.Mine, "mine", cfg.Mine, "producir bloques")
	return fs
}
