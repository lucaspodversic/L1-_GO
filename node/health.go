package node

// Health reporta el estado del nodo para probes.

import "sync/atomic"

// HealthStatus es el informe.
type HealthStatus struct {
	Healthy   bool   `json:"healthy"`
	Syncing   bool   `json:"syncing"`
	Peers     int    `json:"peers"`
	Head      uint64 `json:"head"`
	Finalized uint64 `json:"finalized"`
}

// HealthChecker agrega señales.
type HealthChecker struct {
	syncing   atomic.Bool
	peers     atomic.Int64
	head      atomic.Uint64
	finalized atomic.Uint64
}

// SetSyncing marca sync.
func (h *HealthChecker) SetSyncing(v bool)     { h.syncing.Store(v) }
func (h *HealthChecker) SetPeers(n int)        { h.peers.Store(int64(n)) }
func (h *HealthChecker) SetHead(n uint64)      { h.head.Store(n) }
func (h *HealthChecker) SetFinalized(n uint64) { h.finalized.Store(n) }

// Status construye el informe.
func (h *HealthChecker) Status() HealthStatus {
	return HealthStatus{
		Healthy:   true,
		Syncing:   h.syncing.Load(),
		Peers:     int(h.peers.Load()),
		Head:      h.head.Load(),
		Finalized: h.finalized.Load(),
	}
}
