package node

// Métodos admin_* y l1_*.

import (
	"context"
	"encoding/json"
)

func registerAdmin(s *RPCServer) {
	s.Register("admin_nodeInfo", s.adminNodeInfo)
	s.Register("admin_peers", s.adminPeers)
	s.Register("admin_addPeer", s.adminAddPeer)
	s.Register("l1_metrics", func(context.Context, json.RawMessage) (any, error) {
		return s.node.metrics.Snapshot(), nil
	})
	s.Register("l1_health", func(context.Context, json.RawMessage) (any, error) {
		return s.node.health.Status(), nil
	})
}

func (s *RPCServer) adminNodeInfo(ctx context.Context, _ json.RawMessage) (any, error) {
	id := ""
	listen := ""
	if s.node.identity != nil {
		id = s.node.identity.ID.Hex()
	}
	if s.node.p2p != nil {
		listen = s.node.p2p.ListenAddr()
	}
	return map[string]any{
		"id": id, "listenAddr": listen, "chainId": s.node.cfg.ChainID,
		"genesis": s.node.GenesisHash().Hex(),
	}, nil
}

func (s *RPCServer) adminPeers(ctx context.Context, _ json.RawMessage) (any, error) {
	if s.node.p2p == nil {
		return []any{}, nil
	}
	peers := s.node.p2p.ConnManager().Peers()
	out := make([]string, len(peers))
	for i, p := range peers {
		out[i] = p.Hex()
	}
	return out, nil
}

func (s *RPCServer) adminAddPeer(ctx context.Context, params json.RawMessage) (any, error) {
	var addr string
	if err := parseParams(params, &addr); err != nil {
		return nil, err
	}
	if s.node.p2p == nil {
		return false, nil
	}
	if _, err := s.node.p2p.ConnManager().DialAndAdd(ctx, addr); err != nil {
		return false, ErrServer(-32000, err.Error())
	}
	return true, nil
}
