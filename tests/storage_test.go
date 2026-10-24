package tests

import (
	"testing"

	"github.com/l1/l1/storage"
	"github.com/l1/l1/types"
)

func TestStorageMemoryDBAndState(t *testing.T) {
	db := storage.NewTestDB(t)
	st, err := storage.New(types.EmptyRootHash, db.State)
	if err != nil {
		t.Fatal(err)
	}
	addr := types.Address{0x11}
	st.AddBalance(addr, types.EtherAmount(5))
	if st.GetBalance(addr).Cmp(types.EtherAmount(5)) != 0 {
		t.Fatal("balance")
	}
	root, err := st.Commit(false, true)
	if err != nil || root.IsZero() {
		t.Fatalf("%v %v", root, err)
	}
}
