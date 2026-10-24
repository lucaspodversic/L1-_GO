package mempool

// Este archivo agrupa las métricas del pool: contadores atómicos de
// admisión, rechazo (por motivo), reemplazo, promoción, degradación y
// desalojo, más los tamaños actuales. Snapshot devuelve una copia
// consistente para exportar (RPC, Prometheus en fases posteriores).

import (
	"errors"
	"sync"
	"sync/atomic"
)

// Metrics son los contadores del pool.
type Metrics struct {
	Added     atomic.Uint64
	Rejected  atomic.Uint64
	Replaced  atomic.Uint64
	Promoted  atomic.Uint64
	Demoted   atomic.Uint64
	Evicted   atomic.Uint64
	Discarded atomic.Uint64 // desalojadas por precio con el pool lleno
	Included  atomic.Uint64 // retiradas por haber entrado en un bloque

	mu      sync.Mutex
	reasons map[string]uint64
}

// newMetrics crea las métricas.
func newMetrics() *Metrics { return &Metrics{reasons: make(map[string]uint64)} }

// reasonOf clasifica un error de admisión.
func reasonOf(err error) string {
	for _, e := range []error{ErrAlreadyKnown, ErrInvalidSender, ErrUnderpriced, ErrReplaceUnderpriced, ErrTxPoolOverflow,
		ErrAccountLimit, ErrOversizedData, ErrGasLimit, ErrTipBelowMinimum, ErrNonceGap, ErrFiltered, ErrNonceTooLow,
		ErrInsufficientFunds, ErrIntrinsicGas} {
		if errors.Is(err, e) {
			return e.Error()
		}
	}
	return "otro"
}

// reject cuenta un rechazo.
func (m *Metrics) reject(err error) {
	m.Rejected.Add(1)
	m.mu.Lock()
	m.reasons[reasonOf(err)]++
	m.mu.Unlock()
}

// MetricsSnapshot es una copia de las métricas.
type MetricsSnapshot struct {
	Added, Rejected, Replaced, Promoted, Demoted, Evicted, Discarded, Included uint64
	Reasons                                                                    map[string]uint64
	Pending, Queued                                                            int
}

// Snapshot copia los contadores.
func (m *Metrics) Snapshot() MetricsSnapshot {
	s := MetricsSnapshot{
		Added: m.Added.Load(), Rejected: m.Rejected.Load(), Replaced: m.Replaced.Load(),
		Promoted: m.Promoted.Load(), Demoted: m.Demoted.Load(), Evicted: m.Evicted.Load(),
		Discarded: m.Discarded.Load(), Included: m.Included.Load(), Reasons: map[string]uint64{},
	}
	m.mu.Lock()
	for k, v := range m.reasons {
		s.Reasons[k] = v
	}
	m.mu.Unlock()
	return s
}
