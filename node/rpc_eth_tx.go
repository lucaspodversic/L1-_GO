package node

// Métodos eth_* de transacciones.

import (
	"context"
	"encoding/json"

	"github.com/l1/l1/types"
)

func registerEthTx(s *RPCServer) {
	s.Register("eth_sendRawTransaction", s.ethSendRawTransaction)
	s.Register("eth_getTransactionByHash", s.ethGetTransactionByHash)
	s.Register("eth_getTransactionReceipt", s.ethGetTransactionReceipt)
	s.Register("eth_getTransactionCount", s.ethGetTransactionCount)
}

func (s *RPCServer) ethSendRawTransaction(ctx context.Context, params json.RawMessage) (any, error) {
	var raw types.HexBytes
	if err := parseParams(params, &raw); err != nil {
		return nil, err
	}
	tx, err := types.DecodeTransaction(raw)
	if err != nil {
		return nil, ErrInvalidParams(err.Error())
	}
	if s.node.pool == nil {
		return nil, ErrServer(-32000, "mempool no disponible")
	}
	if err := s.node.pool.SubmitLocal(tx); err != nil {
		return nil, ErrServer(-32000, err.Error())
	}
	_ = s.node.p2p.AnnounceTx(tx)
	s.node.bus.Publish(EventNewTx, tx)
	return tx.Hash(), nil
}

func (s *RPCServer) ethGetTransactionByHash(ctx context.Context, params json.RawMessage) (any, error) {
	var hash types.Hash
	if err := parseParams(params, &hash); err != nil {
		return nil, err
	}
	tx, entry, err := s.node.chain.Transaction(hash)
	if err != nil || tx == nil {
		// Buscar en mempool.
		if s.node.pool != nil {
			if t := s.node.pool.Pool().Get(hash); t != nil {
				return t, nil
			}
		}
		return nil, nil
	}
	_ = entry
	return tx, nil
}

func (s *RPCServer) ethGetTransactionReceipt(ctx context.Context, params json.RawMessage) (any, error) {
	var hash types.Hash
	if err := parseParams(params, &hash); err != nil {
		return nil, err
	}
	tx, entry, err := s.node.chain.Transaction(hash)
	if err != nil || tx == nil || entry == nil {
		return nil, nil
	}
	rs, err := s.node.chain.Receipts(entry.BlockHash)
	if err != nil || int(entry.Index) >= len(rs) {
		return nil, nil
	}
	return rs[entry.Index], nil
}

func (s *RPCServer) ethGetTransactionCount(ctx context.Context, params json.RawMessage) (any, error) {
	var addr types.Address
	var block string
	if err := parseParams(params, &addr, &block); err != nil {
		return nil, err
	}
	h := s.node.chain.CurrentHeader()
	if h == nil {
		return types.HexUint64(0), nil
	}
	st, err := s.node.chain.StateAt(h.StateRoot)
	if err != nil {
		return nil, ErrInternal(err.Error())
	}
	return types.HexUint64(st.GetNonce(addr)), nil
}
