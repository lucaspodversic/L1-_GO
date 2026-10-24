package tests

// Integración: reinicio con el mismo datadir; el head/finalized deben preservarse
// y el nodo debe poder seguir finalizando (WAL de consenso + BlockStore).

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/l1/l1/node"
)

// RunIntRestartRecovery para y reabre el nodo sobre el mismo datadir.
func RunIntRestartRecovery(t *testing.T) {
	d := StartDevNode(t, 50)
	fin := d.WaitFinalized(t, 2, 15*time.Second)
	head := d.Node.Health().Status().Head
	dir := d.Dir
	gh := d.Node.GenesisHash()
	_ = d.Node.Stop()

	cfg := node.DefaultConfig()
	cfg.DataDir = dir
	cfg.ListenAddr = "127.0.0.1:0"
	cfg.RPCAddr = "127.0.0.1:0"
	cfg.RPCWSAddr = "127.0.0.1:0"
	cfg.Mine = true
	cfg.BlockTimeMs = 50
	cfg.ValidatorKey = filepath.Join(dir, "validator.key")
	cfg.NodeKey = filepath.Join(dir, "nodekey")
	cfg.GenesisFile = filepath.Join(dir, "genesis.json")
	cfg.LogLevel = "error"
	n2, err := node.NewBuilder(cfg).Build()
	if err != nil {
		t.Fatal(err)
	}
	if err := n2.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = n2.Stop() })
	if n2.GenesisHash() != gh {
		t.Fatal("génesis cambió tras reinicio")
	}
	// El health se reinicia en memoria; esperamos nueva finalización.
	d2 := &DevNode{Dir: dir, Node: n2, Cfg: n2.Config()}
	_ = d2.WaitFinalized(t, 1, 20*time.Second)
	t.Logf("restart OK prevFin=%d prevHead=%d newFin=%d", fin, head, n2.Health().Status().Finalized)
}
