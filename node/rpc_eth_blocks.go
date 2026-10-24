package node

// Métodos eth_* de bloques.

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/l1/l1/types"
)

func registerEthBlocks(s *RPCServer) {
	s.Register("eth_blockNumber", s.ethBlockNumber)
	s.Register("eth_getBlockByNumber", s.ethGetBlockByNumber)
	s.Register("eth_getBlockByHash", s.ethGetBlockByHash)
	s.Register("eth_chainId", s.ethChainID)
	s.Register("eth_gasPrice", s.ethGasPrice)
	s.Register("eth_protocolVersion", func(context.Context, json.RawMessage) (any, error) {
		return "0x41", nil
	})
	s.Register("eth_syncing", func(context.Context, json.RawMessage) (any, error) { return false, nil })
}

func (s *RPCServer) ethBlockNumber(ctx context.Context, _ json.RawMessage) (any, error) {
	h := s.node.chain.CurrentHeader()
	if h == nil {
		return types.HexUint64(0), nil
	}
	return types.HexUint64(h.Number), nil
}

func (s *RPCServer) ethChainID(ctx context.Context, _ json.RawMessage) (any, error) {
	return types.HexUint64(uint64(s.node.cfg.ChainID)), nil
}

func (s *RPCServer) ethGasPrice(ctx context.Context, _ json.RawMessage) (any, error) {
	h := s.node.chain.CurrentHeader()
	if h == nil {
		return "0x3b9aca00", nil
	}
	return types.HexUint64(h.BaseFee.Uint64()), nil
}

func (s *RPCServer) ethGetBlockByNumber(ctx context.Context, params json.RawMessage) (any, error) {
	var numStr string
	var full bool
	if err := parseParams(params, &numStr, &full); err != nil {
		return nil, err
	}
	n, err := parseBlockNumber(s, numStr)
	if err != nil {
		return nil, err
	}
	b, err := s.node.chain.BlockByNumber(n)
	if err != nil || b == nil {
		return nil, nil
	}
	return BlockToRPC(b, full), nil
}

func (s *RPCServer) ethGetBlockByHash(ctx context.Context, params json.RawMessage) (any, error) {
	var hash types.Hash
	var full bool
	if err := parseParams(params, &hash, &full); err != nil {
		return nil, err
	}
	b, err := s.node.chain.BlockByHash(hash)
	if err != nil || b == nil {
		return nil, nil
	}
	return BlockToRPC(b, full), nil
}

func parseBlockNumber(s *RPCServer, str string) (uint64, error) {
	switch strings.ToLower(str) {
	case "latest", "pending":
		h := s.node.chain.CurrentHeader()
		if h == nil {
			return 0, nil
		}
		return h.Number, nil
	case "earliest", "genesis":
		return 0, nil
	case "finalized", "safe":
		fh, err := s.node.chain.FinalizedHeader()
		if err != nil || fh == nil {
			h := s.node.chain.CurrentHeader()
			if h == nil {
				return 0, nil
			}
			return h.Number, nil
		}
		return fh.Number, nil
	}
	str = strings.TrimPrefix(str, "0x")
	n, err := strconv.ParseUint(str, 16, 64)
	if err != nil {
		return 0, ErrInvalidParams("número de bloque inválido")
	}
	return n, nil
}
