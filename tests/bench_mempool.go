package tests

import (
	"testing"

	"github.com/l1/l1/mempool"
	"github.com/l1/l1/storage"
	"github.com/l1/l1/types"
)

func benchMempool(b *testing.B) {
	st, err := storage.New(types.EmptyRootHash, storage.NewMemoryStateDatabase())
	if err != nil {
		b.Fatal(err)
	}
	h := &types.Header{Number: 0, GasLimit: types.DefaultGasLimit, BaseFee: types.GWeiAmount(1)}
	pool := mempool.New(mempool.DefaultConfig(types.DevnetChainID), h, st)
	to := types.Address{2}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tx := types.NewLegacyTx(types.DevnetChainID, uint64(i), &to, types.NewAmount(1), 21000, types.GWeiAmount(2), nil)
		_ = pool.AddRemote(tx)
	}
}
