package tests

// Integración: preferencia del árbol de bloques (fork choice).

import (
	"testing"
	"time"

	"github.com/l1/l1/consensus"
	"github.com/l1/l1/types"
)

// RunIntReorg construye un BlockTree sobre el génesis y comprueba Insert.
func RunIntReorg(t *testing.T) {
	g := types.DefaultDevGenesis(types.Address{1}, types.GenesisValidator{
		Address: types.Address{1}, BLSPubKey: make([]byte, 48), Power: 1,
	})
	gb := g.ToBlock(types.EmptyRootHash)
	tree := consensus.NewBlockTree(gb, nil)
	if tree.Len() < 1 {
		t.Fatal("árbol vacío")
	}
	if !tree.Contains(gb.Hash()) {
		t.Fatal("raíz no contenida")
	}
	t.Logf("reorg tree root=%s len=%d", gb.Hash().Hex(), tree.Len())
	d := StartDevNode(t, 50)
	d.WaitFinalized(t, 2, 15*time.Second)
}
