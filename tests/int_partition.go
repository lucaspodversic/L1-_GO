package tests

// Integración: partición simulada deteniendo el nodo y reanudando (restart local).
// Una partición de red real requeriría iptables; aquí validamos que tras Stop/Start
// el nodo recupera y sigue finalizando (solape con restart_recovery).

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/l1/l1/node"
)

// RunIntPartition finaliza, para el nodo (partición total), lo vuelve a montar
// sobre el mismo datadir y comprueba que el head no retrocede y avanza.
func RunIntPartition(t *testing.T) {
	if testing.Short() {
		t.Skip("partition omitido en -short")
	}
	d := StartDevNode(t, 50)
	fin := d.WaitFinalized(t, 2, 15*time.Second)
	head := d.Node.Health().Status().Head
	dir := d.Dir
	_ = d.Node.Stop()

	time.Sleep(200 * time.Millisecond)

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
	d2 := &DevNode{Dir: dir, Node: n2, Cfg: n2.Config()}
	fin2 := d2.WaitFinalized(t, fin+1, 20*time.Second)
	if d2.Node.Health().Status().Head < head {
		t.Fatalf("head retrocedió %d -> %d", head, d2.Node.Health().Status().Head)
	}
	t.Logf("partition OK fin %d -> %d", fin, fin2)
}
