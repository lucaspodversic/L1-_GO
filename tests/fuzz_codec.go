package tests

// Núcleo de fuzz para códecs RLP / mensajes de consenso y P2P.

import (
	"testing"

	"github.com/l1/l1/consensus"
	"github.com/l1/l1/p2p"
	"github.com/l1/l1/types"
)

// fuzzCodec registra semillas y ejecuta el objetivo FuzzCodec.
func fuzzCodec(f *testing.F) {
	f.Add([]byte{0x00})
	f.Add(types.EncodeList())
	f.Add(types.EncodeBytes([]byte("hola")))
	f.Add(p2p.EncodeApp(p2p.AppTxAnnounce, []byte{1, 2, 3}))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = consensus.DecodeMessage(data)
		_, _, _ = p2p.DecodeApp(data)
		_, _ = types.DecodeTransaction(data)
	})
}
