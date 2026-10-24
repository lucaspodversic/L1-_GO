package tests

import (
	"testing"

	"github.com/l1/l1/consensus"
	"github.com/l1/l1/types"
)

func TestForkChoiceTreeInsert(t *testing.T) {
	g := types.DefaultDevGenesis(types.Address{1}, types.GenesisValidator{
		Address: types.Address{1}, BLSPubKey: make([]byte, 48), Power: 1,
	})
	root := g.ToBlock(types.EmptyRootHash)
	tree := consensus.NewBlockTree(root, nil)
	if tree.Root().Hash() != root.Hash() {
		t.Fatal("root")
	}
	if tree.PreferredHead() == nil {
		t.Fatal("preferred")
	}
}
