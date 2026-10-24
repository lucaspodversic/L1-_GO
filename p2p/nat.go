package p2p

// NAT best-effort: intenta descubrir la dirección externa vía un peer
// (dirección observada) y, si se configura, registra un mapeo UPnP
// simplificado (aquí sólo la observación; UPnP real requeriría deps).

import (
	"net"
	"sync"
)

// NATManager recuerda la dirección observada por los peers.
type NATManager struct {
	mu       sync.Mutex
	observed map[string]int // addr → votos
	external string
}

// NewNATManager crea el gestor.
func NewNATManager() *NATManager {
	return &NATManager{observed: make(map[string]int)}
}

// Observe registra una dirección externa reportada por un peer.
func (n *NATManager) Observe(addr string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.observed[addr]++
	best, votes := "", 0
	for a, v := range n.observed {
		if v > votes {
			best, votes = a, v
		}
	}
	if votes >= 2 {
		n.external = best
	}
}

// ExternalAddr es la mejor estimación (vacío si desconocida).
func (n *NATManager) ExternalAddr() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.external
}

// LocalAddrs lista las direcciones no-loopback del host.
func LocalAddrs() []string {
	ifaces, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []string
	for _, a := range ifaces {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() {
			continue
		}
		if ip4 := ipnet.IP.To4(); ip4 != nil {
			out = append(out, ip4.String())
		}
	}
	return out
}
