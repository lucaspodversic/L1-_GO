package node

// Configuración del nodo (JSON + flags CLI).

import (
	"time"

	"github.com/l1/l1/types"
)

// Config agrupa todos los parámetros.
type Config struct {
	DataDir      string        `json:"dataDir"`
	ChainID      types.ChainID `json:"chainId"`
	ListenAddr   string        `json:"listenAddr"`
	RPCAddr      string        `json:"rpcAddr"`
	RPCWSAddr    string        `json:"rpcWsAddr"`
	Bootnodes    string        `json:"bootnodes"`
	ValidatorKey string        `json:"validatorKey"`
	NodeKey      string        `json:"nodeKey"`
	GenesisFile  string        `json:"genesis"`
	LogLevel     string        `json:"logLevel"`
	Mine         bool          `json:"mine"` // producir bloques si somos validador
	BlockTimeMs  int           `json:"blockTimeMs"`
	HTTPTimeout  time.Duration `json:"-"`
}

// DefaultConfig valores de desarrollo.
func DefaultConfig() Config {
	return Config{
		DataDir:     "./data",
		ChainID:     types.DevnetChainID,
		ListenAddr:  "127.0.0.1:30303",
		RPCAddr:     "127.0.0.1:8545",
		RPCWSAddr:   "127.0.0.1:8546",
		LogLevel:    "info",
		Mine:        true,
		BlockTimeMs: 200,
		HTTPTimeout: 30 * time.Second,
	}
}
