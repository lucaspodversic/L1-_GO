package tests

import (
	"testing"

	"github.com/l1/l1/mempool"
	"github.com/l1/l1/storage"
	"github.com/l1/l1/types"
)

func TestMempoolAddKnown(t *testing.T) {
	st, err := storage.New(types.EmptyRootHash, storage.NewMemoryStateDatabase())
	if err != nil {
		t.Fatal(err)
	}
	h := &types.Header{Number: 0, GasLimit: types.DefaultGasLimit, BaseFee: types.GWeiAmount(1)}
	pool := mempool.New(mempool.DefaultConfig(types.DevnetChainID), h, st)
	to := types.Address{9}
	tx := types.NewLegacyTx(types.DevnetChainID, 0, &to, types.NewAmount(1), 21000, types.GWeiAmount(2), nil)
	errs := pool.Add([]*types.Transaction{tx}, true)
	t.Logf("Add err=%v pending=%d", errs[0], len(pool.Pending(false)))
}
