package tests

// Integración: cuatro validadores con génesis compartido.
// Se arrancan en cascada para que los bootnodes apunten a peers ya escuchando.

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/l1/l1/consensus"
	"github.com/l1/l1/crypto"
	"github.com/l1/l1/node"
	"github.com/l1/l1/types"
)

func joinBootnodes(addrs []string) string {
	out := ""
	for _, a := range addrs {
		if a == "" {
			continue
		}
		if out != "" {
			out += ","
		}
		out += a
	}
	return out
}

func startFourNodes(t testing.TB) []*DevNode {
	t.Helper()
	if testing.Short() {
		t.Skip("four-nodes omitido en -short")
	}
	root := t.TempDir()
	const n = 4
	type id struct {
		addr types.Address
		vk   *consensus.ValidatorKey
	}
	ids := make([]id, n)
	gvals := make([]types.GenesisValidator, n)
	alloc := map[types.Address]types.GenesisAccount{}
	for i := 0; i < n; i++ {
		sk, err := crypto.GenerateSecp256k1(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		addr := sk.Address()
		vk, err := consensus.GenerateValidatorKey(addr, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		gv, err := consensus.GenesisValidatorFromKey(vk, 1)
		if err != nil {
			t.Fatal(err)
		}
		ids[i] = id{addr: addr, vk: vk}
		gvals[i] = gv
		alloc[addr] = types.GenesisAccount{Balance: types.EtherAmount(1_000_000)}
	}
	gspec := &types.Genesis{
		ChainID: types.DevnetChainID, GasLimit: types.DefaultGasLimit,
		BaseFee: types.NewAmount(types.InitialBaseFee), Consensus: types.DefaultConsensusParams(),
		Alloc: alloc, Validators: gvals,
	}
	gspec.Consensus.BlockTimeMs = 80
	genPath := filepath.Join(root, "genesis.json")
	if err := gspec.Save(genPath); err != nil {
		t.Fatal(err)
	}
	genBytes, _ := os.ReadFile(genPath)

	var boots []string
	out := make([]*DevNode, 0, n)
	for i := 0; i < n; i++ {
		dir := filepath.Join(root, fmt.Sprintf("n%d", i))
		_ = os.MkdirAll(dir, 0o755)
		// nodekey P2P debe ser Ed25519 (no la secp del validador).
		nk, err := crypto.GenerateEd25519(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		_ = crypto.SaveKeyFile(filepath.Join(dir, "nodekey"), nk, "", crypto.LightScryptN)
		_ = consensus.SaveValidatorKey(filepath.Join(dir, "validator.key"), ids[i].vk, "", crypto.LightScryptN)
		_ = os.WriteFile(filepath.Join(dir, "genesis.json"), genBytes, 0o644)

		cfg := node.DefaultConfig()
		cfg.DataDir = dir
		cfg.ListenAddr = "127.0.0.1:0"
		cfg.RPCAddr = "127.0.0.1:0"
		cfg.RPCWSAddr = "127.0.0.1:0"
		cfg.Mine = true
		cfg.BlockTimeMs = 80
		cfg.ValidatorKey = filepath.Join(dir, "validator.key")
		cfg.NodeKey = filepath.Join(dir, "nodekey")
		cfg.GenesisFile = filepath.Join(dir, "genesis.json")
		cfg.LogLevel = "error"
		cfg.Bootnodes = joinBootnodes(boots)

		nd, err := node.NewBuilder(cfg).Build()
		if err != nil {
			t.Fatalf("build %d: %v", i, err)
		}
		if err := nd.Start(); err != nil {
			t.Fatalf("start %d: %v", i, err)
		}
		t.Cleanup(func(nn *node.Node) func() { return func() { _ = nn.Stop() } }(nd))
		boots = append(boots, nd.P2P().ListenAddr())
		out = append(out, &DevNode{Dir: dir, Node: nd, Cfg: nd.Config()})
	}
	return out
}

// RunIntFourNodes verifica génesis compartido y progreso de al menos un nodo.
func RunIntFourNodes(t *testing.T) {
	nodes := startFourNodes(t)
	gh := nodes[0].Node.GenesisHash()
	for i, d := range nodes {
		if d.Node.GenesisHash() != gh {
			t.Fatalf("génesis distinto en nodo %d", i)
		}
	}
	deadline := time.Now().Add(45 * time.Second)
	var best uint64
	for time.Now().Before(deadline) {
		for _, d := range nodes {
			if f := d.Node.Health().Status().Finalized; f > best {
				best = f
			}
		}
		if best >= 1 {
			t.Logf("four-nodes OK finalized=%d peers-bootstrapped=%d", best, len(nodes))
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("four-nodes sin finalización (best=%d); quórum 3/4 requiere gossip de votos", best)
}
