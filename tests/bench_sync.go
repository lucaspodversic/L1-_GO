package tests

import (
	"testing"

	"github.com/l1/l1/p2p"
	"github.com/l1/l1/types"
)

func benchSync(b *testing.B) {
	headers := make([]*types.Header, 100)
	for i := range headers {
		headers[i] = &types.Header{Number: uint64(i), GasLimit: 30_000_000}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		enc := p2p.EncodeHeaders(headers)
		_, payload, err := p2p.DecodeApp(enc)
		if err != nil {
			b.Fatal(err)
		}
		_, err = p2p.DecodeHeaders(payload)
		if err != nil {
			b.Fatal(err)
		}
	}
}
