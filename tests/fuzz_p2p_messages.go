package tests

// Fuzz de mensajes P2P de sync/status/headers.

import (
	"testing"

	"github.com/l1/l1/p2p"
)

func fuzzP2PMessages(f *testing.F) {
	f.Add(p2p.EncodePing())
	f.Add(p2p.EncodeStatus(p2p.StatusMsg{}))
	f.Add(p2p.EncodeGetHeaders(0, 10))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = p2p.DecodeStatus(data)
		_, _ = p2p.DecodeHeaders(data)
		_, _ = p2p.DecodeBodyHashes(data)
		_, _, _ = p2p.DecodeApp(data)
		_, _, _ = p2p.DecodeReq(data)
	})
}
