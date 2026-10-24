package tests

import (
	"testing"

	"github.com/l1/l1/consensus"
	"github.com/l1/l1/types"
)

func benchConsensus(b *testing.B) {
	g := types.DefaultDevGenesis(types.Address{1}, types.GenesisValidator{
		Address: types.Address{1}, BLSPubKey: make([]byte, 48), Power: 1,
	})
	gb := g.ToBlock(types.EmptyRootHash)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tree := consensus.NewBlockTree(gb, nil)
		_ = tree.Len()
	}
}
