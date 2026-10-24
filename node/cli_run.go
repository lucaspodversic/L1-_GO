package node

// Subcomando run.

import (
	"fmt"
)

// cmdRun arranca el nodo y espera señal.
func cmdRun(args []string) error {
	cfg := DefaultConfig()
	fs := RegisterFlags("run", &cfg)
	var configFile string
	fs.StringVar(&configFile, "config", "", "fichero de configuración JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if configFile != "" {
		loaded, err := LoadConfigFile(configFile)
		if err != nil {
			return err
		}
		cfg = loaded
		_ = fs.Parse(args) // flags mandan sobre el fichero
	}
	n, err := NewBuilder(cfg).Build()
	if err != nil {
		return err
	}
	if err := n.Start(); err != nil {
		_ = n.Stop()
		return err
	}
	fmt.Printf("nodo en marcha; genesis=%s rpc=%s ws=%s\n",
		n.GenesisHash().Hex(), n.Config().RPCAddr, n.Config().RPCWSAddr)
	n.Wait()
	return nil
}
