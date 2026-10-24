package tests

// Integración: un nodo minero produce bloques; un segundo nodo (sin mine)
// arranca después y debe poder hablar RPC / compartir génesis (sync best-effort).

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/l1/l1/node"
)

// RunIntSyncNewNode inicia un minero, espera finalización, clona génesis/claves
// de identidad nuevas en un datadir fresco y comprueba que el joiners comparte génesis.
func RunIntSyncNewNode(t *testing.T) {
	if testing.Short() {
		t.Skip("sync omitido en -short")
	}
	miner := StartDevNode(t, 50)
	miner.WaitFinalized(t, 2, 15*time.Second)

	joinDir := t.TempDir()
	// Reutilizar génesis del minero; sin clave validador (no mine).
	gen, err := os.ReadFile(filepath.Join(miner.Dir, "genesis.json"))
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(joinDir, "genesis.json"), gen, 0o644)

	cfg := node.DefaultConfig()
	cfg.DataDir = joinDir
	cfg.ListenAddr = "127.0.0.1:0"
	cfg.RPCAddr = "127.0.0.1:0"
	cfg.RPCWSAddr = "127.0.0.1:0"
	cfg.Mine = false
	cfg.GenesisFile = filepath.Join(joinDir, "genesis.json")
	cfg.Bootnodes = miner.Node.P2P().ListenAddr()
	cfg.LogLevel = "error"
	j, err := node.NewBuilder(cfg).Build()
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = j.Stop() })

	if j.GenesisHash() != miner.Node.GenesisHash() {
		t.Fatal("génesis distinto tras sync join")
	}
	// Esperar un poco a que el sync intente headers.
	time.Sleep(500 * time.Millisecond)
	t.Logf("sync-new-node OK minerFinalized=%d joinerHead=%d",
		miner.Node.Health().Status().Finalized, j.Health().Status().Head)
}
