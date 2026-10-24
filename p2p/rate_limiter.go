package p2p

// Limitador de tasa token-bucket por peer y global.

import (
	"sync"
	"time"
)

// RateLimiter es un token bucket.
type RateLimiter struct {
	mu     sync.Mutex
	rate   float64 // tokens por segundo
	burst  float64
	tokens float64
	last   time.Time
}

// NewRateLimiter crea un bucket que recarga rate tokens/s hasta burst.
func NewRateLimiter(rate, burst float64) *RateLimiter {
	return &RateLimiter{rate: rate, burst: burst, tokens: burst, last: time.Now()}
}

// Allow consume 1 token; false si no hay.
func (r *RateLimiter) Allow() bool { return r.AllowN(1) }

// AllowN consume n tokens.
func (r *RateLimiter) AllowN(n float64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(r.last).Seconds()
	r.tokens += elapsed * r.rate
	if r.tokens > r.burst {
		r.tokens = r.burst
	}
	r.last = now
	if r.tokens < n {
		return false
	}
	r.tokens -= n
	return true
}

// PeerRateLimiter limita por PeerID.
type PeerRateLimiter struct {
	mu    sync.Mutex
	rate  float64
	burst float64
	peers map[PeerID]*RateLimiter
}

// NewPeerRateLimiter crea el mapa.
func NewPeerRateLimiter(rate, burst float64) *PeerRateLimiter {
	return &PeerRateLimiter{rate: rate, burst: burst, peers: make(map[PeerID]*RateLimiter)}
}

// Allow consulta el bucket del peer (creándolo si hace falta).
func (p *PeerRateLimiter) Allow(id PeerID) bool {
	p.mu.Lock()
	r, ok := p.peers[id]
	if !ok {
		r = NewRateLimiter(p.rate, p.burst)
		p.peers[id] = r
	}
	p.mu.Unlock()
	return r.Allow()
}
