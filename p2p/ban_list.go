package p2p

// Lista de peers/IPs baneados temporal o permanentemente.

import (
	"net"
	"sync"
	"time"
)

// BanEntry es una entrada de ban.
type BanEntry struct {
	Until  time.Time // cero = permanente
	Reason string
}

// BanList gestiona bans por PeerID y por IP.
type BanList struct {
	mu    sync.RWMutex
	peers map[PeerID]BanEntry
	ips   map[string]BanEntry
}

// NewBanList crea una lista vacía.
func NewBanList() *BanList {
	return &BanList{peers: make(map[PeerID]BanEntry), ips: make(map[string]BanEntry)}
}

// BanPeer banea un PeerID durante d (0 = permanente).
func (b *BanList) BanPeer(id PeerID, d time.Duration, reason string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	e := BanEntry{Reason: reason}
	if d > 0 {
		e.Until = time.Now().Add(d)
	}
	b.peers[id] = e
}

// BanIP banea una dirección IP.
func (b *BanList) BanIP(ip net.IP, d time.Duration, reason string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	e := BanEntry{Reason: reason}
	if d > 0 {
		e.Until = time.Now().Add(d)
	}
	b.ips[ip.String()] = e
}

// IsBannedPeer indica si el peer está baneado (y limpia expirados).
func (b *BanList) IsBannedPeer(id PeerID) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok := b.peers[id]
	if !ok {
		return false
	}
	if !e.Until.IsZero() && time.Now().After(e.Until) {
		delete(b.peers, id)
		return false
	}
	return true
}

// IsBannedIP igual para IP.
func (b *BanList) IsBannedIP(ip net.IP) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok := b.ips[ip.String()]
	if !ok {
		return false
	}
	if !e.Until.IsZero() && time.Now().After(e.Until) {
		delete(b.ips, ip.String())
		return false
	}
	return true
}

// UnbanPeer quita el ban.
func (b *BanList) UnbanPeer(id PeerID) {
	b.mu.Lock()
	delete(b.peers, id)
	b.mu.Unlock()
}
