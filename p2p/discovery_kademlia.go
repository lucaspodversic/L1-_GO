package p2p

// Descubrimiento Kademlia (XOR metric) simplificado: tablas k-bucket,
// FIND_NODE y PING. No implementa almacenamiento DHT de valores; sólo
// discovery de peers.

import (
	"encoding/binary"
	"sort"
	"sync"
	"time"

	"github.com/l1/l1/types"
)

const (
	kBucketSize   = 16
	alphaParallel = 3
	nBuckets      = 256
)

// DHTNode es una entrada en la tabla de ruteo.
type DHTNode struct {
	ID       PeerID
	Addr     string
	LastSeen time.Time
}

// Kademlia mantiene la tabla de ruteo.
type Kademlia struct {
	mu      sync.Mutex
	self    PeerID
	buckets [nBuckets][]DHTNode
}

// NewKademlia crea la tabla para self.
func NewKademlia(self PeerID) *Kademlia {
	return &Kademlia{self: self}
}

// SelfID es nuestro PeerID.
func (k *Kademlia) SelfID() PeerID { return k.self }

// Distance es el XOR de dos PeerID interpretados como big-endian.
func Distance(a, b PeerID) types.Hash {
	var d types.Hash
	for i := 0; i < 32; i++ {
		d[i] = a[i] ^ b[i]
	}
	return d
}

// bucketIndex es el bit más significativo de la distancia (0 = más lejos).
func bucketIndex(self, id PeerID) int {
	d := Distance(self, id)
	for i := 0; i < 32; i++ {
		if d[i] == 0 {
			continue
		}
		for bit := 0; bit < 8; bit++ {
			if d[i]&(0x80>>bit) != 0 {
				return i*8 + bit
			}
		}
	}
	return nBuckets - 1
}

// Upsert inserta o refresca un nodo.
func (k *Kademlia) Upsert(n DHTNode) {
	if n.ID == k.self {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	idx := bucketIndex(k.self, n.ID)
	b := k.buckets[idx]
	for i := range b {
		if b[i].ID == n.ID {
			b[i] = n
			k.buckets[idx] = b
			return
		}
	}
	n.LastSeen = time.Now()
	if len(b) < kBucketSize {
		k.buckets[idx] = append(b, n)
		return
	}
	// Bucket lleno: reemplaza el más viejo si el nuevo es más reciente.
	oldest := 0
	for i := 1; i < len(b); i++ {
		if b[i].LastSeen.Before(b[oldest].LastSeen) {
			oldest = i
		}
	}
	b[oldest] = n
	k.buckets[idx] = b
}

// Closest devuelve hasta n nodos más cercanos a target.
func (k *Kademlia) Closest(target PeerID, n int) []DHTNode {
	k.mu.Lock()
	defer k.mu.Unlock()
	var all []DHTNode
	for _, b := range k.buckets {
		all = append(all, b...)
	}
	sort.Slice(all, func(i, j int) bool {
		di, dj := Distance(all[i].ID, target), Distance(all[j].ID, target)
		return bytesCmp(di[:], dj[:]) < 0
	})
	if n > len(all) {
		n = len(all)
	}
	return append([]DHTNode(nil), all[:n]...)
}

// Size cuenta entradas.
func (k *Kademlia) Size() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	n := 0
	for _, b := range k.buckets {
		n += len(b)
	}
	return n
}

// EncodeFindNode codifica un pedido FIND_NODE (target).
func EncodeFindNode(target PeerID) []byte {
	return append([]byte{0x01}, target[:]...)
}

// EncodeNeighbors codifica la respuesta.
func EncodeNeighbors(nodes []DHTNode) []byte {
	buf := []byte{0x02}
	var tmp [2]byte
	binary.BigEndian.PutUint16(tmp[:], uint16(len(nodes)))
	buf = append(buf, tmp[:]...)
	for _, n := range nodes {
		buf = append(buf, n.ID[:]...)
		ab := []byte(n.Addr)
		binary.BigEndian.PutUint16(tmp[:], uint16(len(ab)))
		buf = append(buf, tmp[:]...)
		buf = append(buf, ab...)
	}
	return buf
}
