package tests

// Integración: un solo validador (N=1) finaliza bloques y responde por RPC.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/l1/l1/node"
)

// DevNode envuelve un nodo de desarrollo listo para pruebas.
type DevNode struct {
	Dir  string
	Node *node.Node
	Cfg  node.Config
}

// StartDevNode inicializa un datadir --dev, construye y arranca el nodo.
// blockTimeMs controla el ritmo de propuestas (usar 50–100 en tests).
func StartDevNode(t testing.TB, blockTimeMs int) *DevNode {
	t.Helper()
	dir := t.TempDir()
	code := node.Main([]string{
		"init", "--datadir", dir, "--dev",
		"--listen", "127.0.0.1:0",
		"--rpc", "127.0.0.1:0",
		"--ws", "127.0.0.1:0",
	})
	if code != 0 {
		t.Fatalf("init exit %d", code)
	}
	cfg := node.DefaultConfig()
	cfg.DataDir = dir
	cfg.ListenAddr = "127.0.0.1:0"
	cfg.RPCAddr = "127.0.0.1:0"
	cfg.RPCWSAddr = "127.0.0.1:0"
	cfg.Mine = true
	if blockTimeMs <= 0 {
		blockTimeMs = 50
	}
	cfg.BlockTimeMs = blockTimeMs
	cfg.ValidatorKey = filepath.Join(dir, "validator.key")
	cfg.NodeKey = filepath.Join(dir, "nodekey")
	cfg.GenesisFile = filepath.Join(dir, "genesis.json")
	cfg.LogLevel = "error"
	n, err := node.NewBuilder(cfg).Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := n.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = n.Stop() })
	return &DevNode{Dir: dir, Node: n, Cfg: n.Config()}
}

// WaitFinalized espera hasta que Health.Finalized >= min o agota el plazo.
func (d *DevNode) WaitFinalized(t testing.TB, min uint64, timeout time.Duration) uint64 {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var got uint64
	for time.Now().Before(deadline) {
		got = d.Node.Health().Status().Finalized
		if got >= min {
			return got
		}
		time.Sleep(40 * time.Millisecond)
	}
	t.Fatalf("finalized=%d < %d (head=%d)", got, min, d.Node.Health().Status().Head)
	return got
}

// RPCCall ejecuta un método JSON-RPC HTTP contra el nodo.
func (d *DevNode) RPCCall(t testing.TB, method string, params any) json.RawMessage {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	addr := d.Node.Config().RPCAddr
	resp, err := http.Post("http://"+addr+"/", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("rpc %s: %v", method, err)
	}
	defer resp.Body.Close()
	var out struct {
		Result json.RawMessage `json:"result"`
		Error  any             `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Error != nil {
		t.Fatalf("rpc error %s: %v", method, out.Error)
	}
	return out.Result
}

// RunIntSingleNode comprueba finalización ≥2 y eth_blockNumber ≠ 0x0.
func RunIntSingleNode(t *testing.T) {
	d := StartDevNode(t, 50)
	fin := d.WaitFinalized(t, 2, 15*time.Second)
	raw := d.RPCCall(t, "eth_blockNumber", []any{})
	var hexNum string
	if err := json.Unmarshal(raw, &hexNum); err != nil || hexNum == "" || hexNum == "0x0" {
		t.Fatalf("eth_blockNumber=%s err=%v finalized=%d", string(raw), err, fin)
	}
	t.Logf("single-node OK finalized=%d blockNumber=%s", fin, hexNum)
}

// MustAtoiHex convierte "0x.." a uint64 (helper de asserts).
func MustAtoiHex(t testing.TB, s string) uint64 {
	t.Helper()
	var v uint64
	_, err := fmt.Sscanf(s, "0x%x", &v)
	if err != nil {
		t.Fatalf("hex %q: %v", s, err)
	}
	return v
}
