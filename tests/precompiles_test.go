package tests

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/l1/l1/execution"
	"github.com/l1/l1/storage"
	"github.com/l1/l1/types"
)

func TestPrecompileSHA256(t *testing.T) {
	st, _ := storage.New(types.EmptyRootHash, storage.NewMemoryStateDatabase())
	h := &types.Header{Number: 1, GasLimit: 30_000_000, BaseFee: types.GWeiAmount(1)}
	evm := execution.NewEVM(execution.NewEVMBlockContext(h, nil, nil), execution.TxContext{}, st, nil, execution.Config{})
	out, _, err := evm.Call(types.Address{1}, types.BytesToAddress([]byte{2}), []byte("abc"), 1_000_000, execution.NewWord(0))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("abc"))
	if !bytes.Equal(out, sum[:]) {
		t.Fatal("sha256 precompile")
	}
	if !execution.IsPrecompile(types.BytesToAddress([]byte{1})) {
		t.Fatal("ecrecover addr")
	}
}
