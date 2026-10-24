package tests

import (
	"testing"

	"github.com/l1/l1/storage"
	"github.com/l1/l1/types"
)

func TestStateRevertSnapshot(t *testing.T) {
	st, err := storage.New(types.EmptyRootHash, storage.NewMemoryStateDatabase())
	if err != nil {
		t.Fatal(err)
	}
	a := types.Address{1}
	st.AddBalance(a, types.EtherAmount(10))
	snap := st.Snapshot()
	st.AddBalance(a, types.EtherAmount(5))
	if st.GetBalance(a).Cmp(types.EtherAmount(15)) != 0 {
		t.Fatal("pre-revert")
	}
	st.RevertToSnapshot(snap)
	if st.GetBalance(a).Cmp(types.EtherAmount(10)) != 0 {
		t.Fatalf("post-revert %s", st.GetBalance(a))
	}
}
