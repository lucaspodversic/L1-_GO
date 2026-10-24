package node

// Métodos net_*.

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/l1/l1/types"
)

func registerNet(s *RPCServer) {
	s.Register("net_version", func(context.Context, json.RawMessage) (any, error) {
		return fmt.Sprintf("%d", uint64(s.node.cfg.ChainID)), nil
	})
	s.Register("net_listening", func(context.Context, json.RawMessage) (any, error) {
		return true, nil
	})
	s.Register("net_peerCount", func(context.Context, json.RawMessage) (any, error) {
		n := 0
		if s.node.p2p != nil {
			n = s.node.p2p.PeerCount()
		}
		return types.HexUint64(uint64(n)), nil
	})
}
