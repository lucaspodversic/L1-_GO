package mempool

// Este archivo mantiene el "nonce pendiente" de cada cuenta: el siguiente
// nonce que tendría la cuenta si se ejecutaran todas sus transacciones
// ejecutables del pool. Es lo que devuelve eth_getTransactionCount con
// "pending" y lo que usa el pool para decidir qué es ejecutable. Si una
// cuenta no está en el mapa se consulta el estado (nonce confirmado).

import (
	"sync"

	"github.com/l1/l1/types"
)

// nonceTracker es seguro para uso concurrente.
type nonceTracker struct {
	mu     sync.RWMutex
	state  StateReader
	nonces map[types.Address]uint64
}

// newNonceTracker crea el rastreador sobre un estado.
func newNonceTracker(state StateReader) *nonceTracker {
	return &nonceTracker{state: state, nonces: make(map[types.Address]uint64)}
}

// get devuelve el nonce pendiente (cacheándolo desde el estado).
func (t *nonceTracker) get(addr types.Address) uint64 {
	t.mu.RLock()
	n, ok := t.nonces[addr]
	t.mu.RUnlock()
	if ok {
		return n
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if n, ok := t.nonces[addr]; ok {
		return n
	}
	n = t.state.GetNonce(addr)
	t.nonces[addr] = n
	return n
}

// set fija el nonce pendiente.
func (t *nonceTracker) set(addr types.Address, n uint64) {
	t.mu.Lock()
	t.nonces[addr] = n
	t.mu.Unlock()
}

// setIfLower baja el nonce pendiente (cuando se retira una tx pendiente,
// las posteriores dejan de ser ejecutables).
func (t *nonceTracker) setIfLower(addr types.Address, n uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	cur, ok := t.nonces[addr]
	if !ok {
		cur = t.state.GetNonce(addr)
	}
	if n < cur {
		t.nonces[addr] = n
	} else {
		t.nonces[addr] = cur
	}
}

// reset descarta la caché y cambia el estado base (nuevo bloque).
func (t *nonceTracker) reset(state StateReader) {
	t.mu.Lock()
	t.state = state
	clear(t.nonces)
	t.mu.Unlock()
}

// setAll reemplaza los nonces pendientes por los dados.
func (t *nonceTracker) setAll(all map[types.Address]uint64) {
	t.mu.Lock()
	clear(t.nonces)
	for a, n := range all {
		t.nonces[a] = n
	}
	t.mu.Unlock()
}
