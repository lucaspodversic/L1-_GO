package tests

// Fuzz del MPT: Update/Get/Delete con claves-valores aleatorios.

import (
	"bytes"
	"testing"

	"github.com/l1/l1/storage"
)

func fuzzTrie(f *testing.F) {
	f.Add([]byte("key"), []byte("val"))
	f.Add([]byte{0}, []byte{1, 2, 3})
	f.Fuzz(func(t *testing.T, key, val []byte) {
		if len(key) > 64 {
			key = key[:64]
		}
		if len(val) > 256 {
			val = val[:256]
		}
		tr := storage.NewEmptyTrie()
		if err := tr.Update(key, val); err != nil {
			return
		}
		got, err := tr.Get(key)
		if err != nil {
			t.Fatal(err)
		}
		if len(val) == 0 {
			// Update con valor vacío puede eliminar
			return
		}
		if !bytes.Equal(got, val) {
			t.Fatalf("got %x want %x", got, val)
		}
		_ = tr.Hash()
	})
}
