package node

// Tipos JSON-RPC y helpers hex de estilo Ethereum.

import (
	"encoding/json"

	"github.com/l1/l1/types"
)

// RPCRequest es una petición JSON-RPC 2.0.
type RPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

// RPCResponse es la respuesta.
type RPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// RPCBlock es la vista JSON de un bloque (estilo geth).
type RPCBlock struct {
	Number           types.HexUint64  `json:"number"`
	Hash             types.Hash       `json:"hash"`
	ParentHash       types.Hash       `json:"parentHash"`
	Nonce            string           `json:"nonce"`
	Sha3Uncles       types.Hash       `json:"sha3Uncles"`
	LogsBloom        types.Bloom      `json:"logsBloom"`
	TransactionsRoot types.Hash       `json:"transactionsRoot"`
	StateRoot        types.Hash       `json:"stateRoot"`
	ReceiptsRoot     types.Hash       `json:"receiptsRoot"`
	Miner            types.Address    `json:"miner"`
	Difficulty       string           `json:"difficulty"`
	TotalDifficulty  string           `json:"totalDifficulty"`
	ExtraData        types.HexBytes   `json:"extraData"`
	Size             types.HexUint64  `json:"size"`
	GasLimit         types.HexUint64  `json:"gasLimit"`
	GasUsed          types.HexUint64  `json:"gasUsed"`
	Timestamp        types.HexUint64  `json:"timestamp"`
	Transactions     any              `json:"transactions"`
	Uncles           []types.Hash     `json:"uncles"`
	BaseFeePerGas    *types.HexUint64 `json:"baseFeePerGas,omitempty"`
	Epoch            types.HexUint64  `json:"epoch"`
	View             types.HexUint64  `json:"view"`
}

// HeaderToRPC convierte una cabecera (+hash) a RPCBlock sin txs.
func HeaderToRPC(h *types.Header, hash types.Hash, txHashes []types.Hash) *RPCBlock {
	base := types.HexUint64(0)
	if !h.BaseFee.IsZero() {
		base = types.HexUint64(h.BaseFee.Uint64())
	}
	txs := any(txHashes)
	if txHashes == nil {
		txs = []types.Hash{}
	}
	return &RPCBlock{
		Number: types.HexUint64(h.Number), Hash: hash, ParentHash: h.ParentHash,
		Nonce: "0x0000000000000000", LogsBloom: h.LogsBloom,
		TransactionsRoot: h.TxRoot, StateRoot: h.StateRoot, ReceiptsRoot: h.ReceiptRoot,
		Miner: h.Proposer, Difficulty: "0x1", TotalDifficulty: "0x1",
		ExtraData: h.ExtraData, GasLimit: types.HexUint64(h.GasLimit),
		GasUsed: types.HexUint64(h.GasUsed), Timestamp: types.HexUint64(h.Timestamp),
		Transactions: txs, Uncles: []types.Hash{}, BaseFeePerGas: &base,
		Epoch: types.HexUint64(h.Epoch), View: types.HexUint64(h.View),
	}
}

// BlockToRPC convierte un bloque.
func BlockToRPC(b *types.Block, fullTx bool) *RPCBlock {
	var txs any
	if fullTx {
		list := make([]*types.Transaction, len(b.Transactions()))
		copy(list, b.Transactions())
		txs = list
	} else {
		txs = b.Transactions().Hashes()
	}
	h := b.HeaderRef()
	rpc := HeaderToRPC(h, b.Hash(), nil)
	rpc.Transactions = txs
	rpc.Size = types.HexUint64(b.Size())
	return rpc
}
