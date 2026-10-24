package node

// Contadores y gauges simples en memoria (exportables por RPC admin).

import "sync/atomic"

// NewMetrics crea el registro de métricas.
func NewMetrics() *Metrics { return &Metrics{} }

// Metrics agrega métricas del nodo.
type Metrics struct {
	BlocksFinalized atomic.Uint64
	BlocksProposed  atomic.Uint64
	TxsIncluded     atomic.Uint64
	Peers           atomic.Int64
	RPCRequests     atomic.Uint64
	P2PMessages     atomic.Uint64
}

// Snapshot es una copia estable.
type MetricsSnapshot struct {
	BlocksFinalized uint64 `json:"blocksFinalized"`
	BlocksProposed  uint64 `json:"blocksProposed"`
	TxsIncluded     uint64 `json:"txsIncluded"`
	Peers           int64  `json:"peers"`
	RPCRequests     uint64 `json:"rpcRequests"`
	P2PMessages     uint64 `json:"p2pMessages"`
}

// Snapshot captura los valores actuales.
func (m *Metrics) Snapshot() MetricsSnapshot {
	return MetricsSnapshot{
		BlocksFinalized: m.BlocksFinalized.Load(),
		BlocksProposed:  m.BlocksProposed.Load(),
		TxsIncluded:     m.TxsIncluded.Load(),
		Peers:           m.Peers.Load(),
		RPCRequests:     m.RPCRequests.Load(),
		P2PMessages:     m.P2PMessages.Load(),
	}
}
