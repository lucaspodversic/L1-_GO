package tests

import (
	"testing"

	"github.com/l1/l1/execution"
	"github.com/l1/l1/storage"
	"github.com/l1/l1/types"
)

func benchVM(b *testing.B) {
	st, err := storage.New(types.EmptyRootHash, storage.NewMemoryStateDatabase())
	if err != nil {
		b.Fatal(err)
	}
	addr := types.Address{0x42}
	code := []byte{0x60, 2, 0x60, 3, 0x01, 0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xf3}
	st.SetCode(addr, code)
	st.AddBalance(types.Address{1}, types.EtherAmount(1))
	h := &types.Header{Number: 1, GasLimit: 30_000_000, BaseFee: types.GWeiAmount(1)}
	evm := execution.NewEVM(execution.NewEVMBlockContext(h, nil, nil), execution.TxContext{}, st, nil, execution.Config{})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		st.Prepare(types.Address{1}, types.Address{}, &addr, nil, nil)
		_, _, err := evm.Call(types.Address{1}, addr, nil, 100000, execution.NewWord(0))
		if err != nil {
			b.Fatal(err)
		}
	}
}
