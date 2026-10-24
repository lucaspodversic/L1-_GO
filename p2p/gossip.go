package p2p

// Gossipsub simplificado: difusión a todos los peers conectados con
// deduplicación por MessageID (hash del payload).

import (
	"sync"
	"time"

	"github.com/l1/l1/crypto"
	"github.com/l1/l1/types"
)

// GossipHandler procesa un mensaje de un topic.
type GossipHandler func(from PeerID, topic string, data []byte)

// Gossip es el difusor.
type Gossip struct {
	mu       sync.Mutex
	seen     map[types.Hash]time.Time
	handlers map[string][]GossipHandler
	send     func(id PeerID, msg []byte) error
	peers    func() []PeerID
	ttl      time.Duration
}

// NewGossip crea el módulo.
func NewGossip(send func(PeerID, []byte) error, peers func() []PeerID) *Gossip {
	return &Gossip{
		seen:     make(map[types.Hash]time.Time),
		handlers: make(map[string][]GossipHandler),
		send:     send, peers: peers, ttl: 10 * time.Minute,
	}
}

// Subscribe registra un handler para un topic.
func (g *Gossip) Subscribe(topic string, h GossipHandler) {
	g.mu.Lock()
	g.handlers[topic] = append(g.handlers[topic], h)
	g.mu.Unlock()
}

// Publish difunde data en topic a todos los peers (excepto skip).
func (g *Gossip) Publish(topic string, data []byte, skip PeerID) error {
	id := crypto.Keccak256Hash(append([]byte(topic), data...))
	g.mu.Lock()
	if _, ok := g.seen[id]; ok {
		g.mu.Unlock()
		return nil
	}
	g.seen[id] = time.Now()
	g.mu.Unlock()
	payload := append([]byte(topic+"\x00"), data...)
	msg := EncodeApp(AppGossip, payload)
	for _, p := range g.peers() {
		if p == skip {
			continue
		}
		_ = g.send(p, msg)
	}
	return nil
}

// Handle procesa un mensaje gossip entrante.
func (g *Gossip) Handle(from PeerID, payload []byte) {
	// payload = topic\x00data
	sep := -1
	for i, c := range payload {
		if c == 0 {
			sep = i
			break
		}
	}
	if sep < 0 {
		return
	}
	topic := string(payload[:sep])
	data := payload[sep+1:]
	id := crypto.Keccak256Hash(append([]byte(topic), data...))
	g.mu.Lock()
	if _, ok := g.seen[id]; ok {
		g.mu.Unlock()
		return
	}
	g.seen[id] = time.Now()
	hs := append([]GossipHandler(nil), g.handlers[topic]...)
	g.mu.Unlock()
	for _, h := range hs {
		h(from, topic, data)
	}
	// Retransmisión.
	_ = g.Publish(topic, data, from)
}

// GC elimina entradas viejas del set de vistos.
func (g *Gossip) GC() {
	g.mu.Lock()
	defer g.mu.Unlock()
	cut := time.Now().Add(-g.ttl)
	for id, t := range g.seen {
		if t.Before(cut) {
			delete(g.seen, id)
		}
	}
}
