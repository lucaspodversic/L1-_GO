package p2p

// ConnectionManager mantiene el conjunto de conexiones activas, aplica
// límites inbound/outbound, ban-list y rate limiting.

import (
	"context"
	"net"
	"sync"
	"time"
)

// ConnManagerConfig límites.
type ConnManagerConfig struct {
	MaxInbound  int
	MaxOutbound int
	DialTimeout time.Duration
}

// DefaultConnManagerConfig valores por defecto.
func DefaultConnManagerConfig() ConnManagerConfig {
	return ConnManagerConfig{MaxInbound: 50, MaxOutbound: 25, DialTimeout: 10 * time.Second}
}

// ConnManager gestiona conexiones.
type ConnManager struct {
	mu        sync.Mutex
	cfg       ConnManagerConfig
	transport *Transport
	bans      *BanList
	limiter   *PeerRateLimiter
	conns     map[PeerID]*Conn
	inbound   int
	outbound  int
	onConn    func(*Conn, bool) // bool = inbound
	onMsg     func(PeerID, []byte)
}

// NewConnManager crea el gestor.
func NewConnManager(t *Transport, bans *BanList, cfg ConnManagerConfig) *ConnManager {
	if bans == nil {
		bans = NewBanList()
	}
	return &ConnManager{
		cfg: cfg, transport: t, bans: bans,
		limiter: NewPeerRateLimiter(100, 200),
		conns:   make(map[PeerID]*Conn),
	}
}

// OnConn registra callback de nueva conexión.
func (m *ConnManager) OnConn(h func(*Conn, bool)) { m.onConn = h }

// OnMessage registra callback de mensaje.
func (m *ConnManager) OnMessage(h func(PeerID, []byte)) { m.onMsg = h }

// Peers lista los PeerID conectados.
func (m *ConnManager) Peers() []PeerID {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]PeerID, 0, len(m.conns))
	for id := range m.conns {
		out = append(out, id)
	}
	return out
}

// Len número de conexiones.
func (m *ConnManager) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.conns)
}

// Send envía a un peer concreto.
func (m *ConnManager) Send(id PeerID, msg []byte) error {
	m.mu.Lock()
	c := m.conns[id]
	m.mu.Unlock()
	if c == nil {
		return ErrHandshake // reuse as "no conn"
	}
	return c.Send(msg)
}

// Broadcast envía a todos.
func (m *ConnManager) Broadcast(msg []byte) {
	for _, id := range m.Peers() {
		_ = m.Send(id, msg)
	}
}

// AddInbound registra una conexión aceptada.
func (m *ConnManager) AddInbound(c *Conn) bool {
	ip, _, _ := net.SplitHostPort(c.RemoteAddr().String())
	if m.bans.IsBannedPeer(c.RemoteID()) || m.bans.IsBannedIP(net.ParseIP(ip)) {
		c.Close()
		return false
	}
	m.mu.Lock()
	if m.inbound >= m.cfg.MaxInbound {
		m.mu.Unlock()
		c.Close()
		return false
	}
	if _, ok := m.conns[c.RemoteID()]; ok {
		m.mu.Unlock()
		c.Close()
		return false
	}
	m.conns[c.RemoteID()] = c
	m.inbound++
	m.mu.Unlock()
	if m.onConn != nil {
		m.onConn(c, true)
	}
	go m.readLoop(c)
	return true
}

// DialAndAdd diala y registra como outbound.
func (m *ConnManager) DialAndAdd(ctx context.Context, addr string) (*Conn, error) {
	m.mu.Lock()
	if m.outbound >= m.cfg.MaxOutbound {
		m.mu.Unlock()
		return nil, net.ErrClosed
	}
	m.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, m.cfg.DialTimeout)
	defer cancel()
	c, err := m.transport.Dial(ctx, addr)
	if err != nil {
		return nil, err
	}
	if m.bans.IsBannedPeer(c.RemoteID()) {
		c.Close()
		return nil, ErrHandshake
	}
	m.mu.Lock()
	if _, ok := m.conns[c.RemoteID()]; ok {
		m.mu.Unlock()
		c.Close()
		return nil, ErrHandshake
	}
	m.conns[c.RemoteID()] = c
	m.outbound++
	m.mu.Unlock()
	if m.onConn != nil {
		m.onConn(c, false)
	}
	go m.readLoop(c)
	return c, nil
}

func (m *ConnManager) readLoop(c *Conn) {
	defer m.remove(c)
	for {
		msg, err := c.Receive()
		if err != nil {
			return
		}
		if !m.limiter.Allow(c.RemoteID()) {
			continue
		}
		if m.onMsg != nil {
			m.onMsg(c.RemoteID(), msg)
		}
	}
}

func (m *ConnManager) remove(c *Conn) {
	m.mu.Lock()
	if cur, ok := m.conns[c.RemoteID()]; ok && cur == c {
		delete(m.conns, c.RemoteID())
	}
	m.mu.Unlock()
	_ = c.Close()
}

// CloseAll cierra todas las conexiones.
func (m *ConnManager) CloseAll() {
	m.mu.Lock()
	conns := make([]*Conn, 0, len(m.conns))
	for _, c := range m.conns {
		conns = append(conns, c)
	}
	m.conns = make(map[PeerID]*Conn)
	m.inbound, m.outbound = 0, 0
	m.mu.Unlock()
	for _, c := range conns {
		c.Close()
	}
}

// Get recupera una conexión.
func (m *ConnManager) Get(id PeerID) *Conn {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.conns[id]
}
