package tests

import (
	"fmt"
	"testing"

	"github.com/l1/l1/storage"
)

func benchTrie(b *testing.B) {
	keys := make([][]byte, 1000)
	for i := range keys {
		keys[i] = []byte(fmt.Sprintf("key-%d", i))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tr := storage.NewEmptyTrie()
		for j, k := range keys {
			_ = tr.Update(k, []byte{byte(j)})
		}
		_ = tr.Hash()
	}
}
