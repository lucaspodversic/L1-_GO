package tests

import (
	"sync/atomic"
	"testing"

	"github.com/l1/l1/p2p"
)

func TestGossipPublishDedup(t *testing.T) {
	var sent atomic.Int32
	g := p2p.NewGossip(func(id p2p.PeerID, msg []byte) error {
		sent.Add(1)
		return nil
	}, func() []p2p.PeerID { return []p2p.PeerID{{1}, {2}} })
	if err := g.Publish("tx", []byte("hola"), p2p.PeerID{}); err != nil {
		t.Fatal(err)
	}
	if sent.Load() != 2 {
		t.Fatalf("sent=%d", sent.Load())
	}
	// Segunda publicación idéntica no reenvía (seen).
	_ = g.Publish("tx", []byte("hola"), p2p.PeerID{})
	if sent.Load() != 2 {
		t.Fatalf("dedup falló sent=%d", sent.Load())
	}
}
