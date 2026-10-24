package tests

import (
	"math/big"
	"testing"

	"github.com/l1/l1/execution"
	"github.com/l1/l1/storage"
	"github.com/l1/l1/types"
)

func TestVMOpcodesAddReturn(t *testing.T) {
	st, err := storage.New(types.EmptyRootHash, storage.NewMemoryStateDatabase())
	if err != nil {
		t.Fatal(err)
	}
	c := types.Address{0xc0}
	st.SetCode(c, fixtureReturn5())
	h := fixtureHeader(1)
	evm := execution.NewEVM(execution.NewEVMBlockContext(h, nil, nil), execution.TxContext{}, st, nil, execution.Config{})
	st.Prepare(types.Address{1}, types.Address{}, &c, evm.ActivePrecompileAddresses(), nil)
	ret, _, err := evm.Call(types.Address{1}, c, nil, 100000, execution.NewWord(0))
	if err != nil {
		t.Fatal(err)
	}
	if new(big.Int).SetBytes(ret).Int64() != 5 {
		t.Fatalf("ret %x", ret)
	}
	if !execution.PUSH1.IsPush() {
		t.Fatal("PUSH1")
	}
	if execution.OpCode(0x01).String() == "" {
		t.Fatal("ADD name")
	}
}
