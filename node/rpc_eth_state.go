package node

// Métodos eth_* de estado y llamada.

import (
	"context"
	"encoding/json"

	"github.com/l1/l1/execution"
	"github.com/l1/l1/types"
)

func registerEthState(s *RPCServer) {
	s.Register("eth_getBalance", s.ethGetBalance)
	s.Register("eth_getCode", s.ethGetCode)
	s.Register("eth_getStorageAt", s.ethGetStorageAt)
	s.Register("eth_call", s.ethCall)
	s.Register("eth_estimateGas", s.ethEstimateGas)
}

func (s *RPCServer) ethGetBalance(ctx context.Context, params json.RawMessage) (any, error) {
	var addr types.Address
	var block string
	if err := parseParams(params, &addr, &block); err != nil {
		return nil, err
	}
	h := s.node.chain.CurrentHeader()
	if h == nil {
		return "0x0", nil
	}
	st, err := s.node.chain.StateAt(h.StateRoot)
	if err != nil {
		return nil, ErrInternal(err.Error())
	}
	return types.HexBytes(st.GetBalance(addr).Bytes()), nil
}

func (s *RPCServer) ethGetCode(ctx context.Context, params json.RawMessage) (any, error) {
	var addr types.Address
	var block string
	if err := parseParams(params, &addr, &block); err != nil {
		return nil, err
	}
	h := s.node.chain.CurrentHeader()
	if h == nil {
		return types.HexBytes{}, nil
	}
	st, err := s.node.chain.StateAt(h.StateRoot)
	if err != nil {
		return nil, ErrInternal(err.Error())
	}
	return types.HexBytes(st.GetCode(addr)), nil
}

func (s *RPCServer) ethGetStorageAt(ctx context.Context, params json.RawMessage) (any, error) {
	var addr types.Address
	var slot types.Hash
	var block string
	if err := parseParams(params, &addr, &slot, &block); err != nil {
		return nil, err
	}
	h := s.node.chain.CurrentHeader()
	if h == nil {
		return types.Hash{}, nil
	}
	st, err := s.node.chain.StateAt(h.StateRoot)
	if err != nil {
		return nil, ErrInternal(err.Error())
	}
	return st.GetState(addr, slot), nil
}

// rpcCallArgs es la forma JSON de eth_call.
type rpcCallArgs struct {
	From  *types.Address   `json:"from"`
	To    *types.Address   `json:"to"`
	Gas   *types.HexUint64 `json:"gas"`
	Value *types.HexBytes  `json:"value"`
	Data  *types.HexBytes  `json:"data"`
	Input *types.HexBytes  `json:"input"`
}

func parseCallArgs(raw json.RawMessage) (execution.CallArgs, error) {
	var a rpcCallArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return execution.CallArgs{}, ErrInvalidParams(err.Error())
	}
	out := execution.CallArgs{}
	if a.From != nil {
		out.From = *a.From
	}
	out.To = a.To
	if a.Gas != nil {
		out.Gas = uint64(*a.Gas)
	}
	if a.Value != nil && len(*a.Value) > 0 {
		out.Value = mustAmount(*a.Value)
	}
	data := a.Data
	if data == nil {
		data = a.Input
	}
	if data != nil {
		out.Data = []byte(*data)
	}
	return out, nil
}

func (s *RPCServer) ethCall(ctx context.Context, params json.RawMessage) (any, error) {
	var arr []json.RawMessage
	if err := json.Unmarshal(params, &arr); err != nil || len(arr) < 1 {
		return nil, ErrInvalidParams("eth_call espera [callObject, block]")
	}
	args, err := parseCallArgs(arr[0])
	if err != nil {
		return nil, err
	}
	h := s.node.chain.CurrentHeader()
	if h == nil {
		return nil, ErrServer(-32000, "sin cabecera")
	}
	res, err := s.node.exec.Call(ctx, args, h)
	if err != nil {
		return nil, ErrServer(-32000, err.Error())
	}
	return types.HexBytes(res.ReturnData), nil
}

func (s *RPCServer) ethEstimateGas(ctx context.Context, params json.RawMessage) (any, error) {
	var arr []json.RawMessage
	if err := json.Unmarshal(params, &arr); err != nil || len(arr) < 1 {
		return nil, ErrInvalidParams("eth_estimateGas espera [callObject, block?]")
	}
	args, err := parseCallArgs(arr[0])
	if err != nil {
		return nil, err
	}
	h := s.node.chain.CurrentHeader()
	if h == nil {
		return nil, ErrServer(-32000, "sin cabecera")
	}
	gas, err := s.node.exec.EstimateGas(ctx, args, h)
	if err != nil {
		return nil, ErrServer(-32000, err.Error())
	}
	return types.HexUint64(gas), nil
}

func mustAmount(b []byte) types.Amount {
	a, err := types.AmountFromBytes(b)
	if err != nil {
		return types.Amount{}
	}
	return a
}
