package tests

// Fuzz del intérprete EVM: bytecode arbitrario no debe paniqueear.

import (
	"testing"

	"github.com/l1/l1/execution"
	"github.com/l1/l1/storage"
	"github.com/l1/l1/types"
)

func fuzzVM(f *testing.F) {
	f.Add([]byte{0x00})                               // STOP
	f.Add([]byte{0x60, 0x01, 0x60, 0x02, 0x01, 0x00}) // ADD STOP
	f.Fuzz(func(t *testing.T, code []byte) {
		if len(code) > 2048 {
			code = code[:2048]
		}
		st, err := storage.New(types.EmptyRootHash, storage.NewMemoryStateDatabase())
		if err != nil {
			t.Fatal(err)
		}
		addr := types.Address{0x42}
		st.SetCode(addr, code)
		st.AddBalance(types.Address{1}, types.EtherAmount(1))
		h := &types.Header{Number: 1, GasLimit: 1_000_000, BaseFee: types.GWeiAmount(1)}
		evm := execution.NewEVM(execution.NewEVMBlockContext(h, nil, nil), execution.TxContext{}, st, nil, execution.Config{})
		st.Prepare(types.Address{1}, types.Address{}, &addr, nil, nil)
		_, _, _ = evm.Call(types.Address{1}, addr, nil, 100000, execution.NewWord(0))
	})
}
