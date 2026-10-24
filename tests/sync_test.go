package tests

import (
	"testing"

	"github.com/l1/l1/p2p"
	"github.com/l1/l1/types"
)

func TestSyncHeadersCodec(t *testing.T) {
	hs := []*types.Header{{Number: 1, GasLimit: 100}, {Number: 2, GasLimit: 100}}
	full := p2p.EncodeHeaders(hs)
	_, payload, err := p2p.DecodeApp(full)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := p2p.DecodeHeaders(payload)
	if err != nil || len(dec) != 2 || dec[1].Number != 2 {
		t.Fatalf("%v %v", dec, err)
	}
	fullS := p2p.EncodeStatus(p2p.StatusMsg{Genesis: types.Hash{1}, Number: 7})
	_, sp, err := p2p.DecodeApp(fullS)
	if err != nil {
		t.Fatal(err)
	}
	got, err := p2p.DecodeStatus(sp)
	if err != nil || got.Number != 7 {
		t.Fatal(err, got)
	}
}
