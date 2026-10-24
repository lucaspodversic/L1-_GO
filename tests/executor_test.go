package tests

import (
	"testing"

	"github.com/l1/l1/execution"
	"github.com/l1/l1/storage"
	"github.com/l1/l1/types"
)

func TestExecutorCreateAndCall(t *testing.T) {
	st, _ := storage.New(types.EmptyRootHash, storage.NewMemoryStateDatabase())
	caller := types.Address{0xca}
	st.AddBalance(caller, types.EtherAmount(10))
	h := &types.Header{Number: 1, GasLimit: 30_000_000, BaseFee: types.GWeiAmount(1)}
	evm := execution.NewEVM(execution.NewEVMBlockContext(h, nil, nil), execution.TxContext{Origin: caller}, st, nil, execution.Config{})
	st.Prepare(caller, caller, nil, evm.ActivePrecompileAddresses(), nil)
	init := execution.Assemble(
		execution.PUSH1, byte(0), execution.PUSH1, byte(0), execution.RETURN,
	)
	_, addr, _, err := evm.Create(caller, init, 500000, execution.NewWord(0))
	if err != nil || addr.IsZero() {
		t.Fatalf("%v %s", err, addr.Hex())
	}
}
