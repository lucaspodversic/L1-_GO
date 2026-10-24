package tests

import (
	"bytes"
	"testing"

	"github.com/l1/l1/storage"
)

func TestTrieUpdateGetCommit(t *testing.T) {
	tr := storage.NewEmptyTrie()
	if err := tr.Update([]byte("dog"), []byte("puppy")); err != nil {
		t.Fatal(err)
	}
	if err := tr.Update([]byte("doe"), []byte("reindeer")); err != nil {
		t.Fatal(err)
	}
	v, err := tr.Get([]byte("dog"))
	if err != nil || !bytes.Equal(v, []byte("puppy")) {
		t.Fatalf("%x %v", v, err)
	}
	root, ns := tr.Commit()
	if root.IsZero() || ns == nil {
		t.Fatal("commit")
	}
}
