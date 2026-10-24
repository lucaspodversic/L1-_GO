package p2p

// PeerStore recuerda direcciones conocidas (bootnodes, peers descubiertos)
// con persistencia opcional en JSON.

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// PeerRecord describe un peer conocido.
type PeerRecord struct {
	ID        PeerID    `json:"id"`
	Addrs     []string  `json:"addrs"`
	LastSeen  time.Time `json:"lastSeen"`
	Score     float64   `json:"score"`
	Direction string    `json:"direction,omitempty"` // inbound/outbound
}

// PeerStore es un almacén concurrente de PeerRecord.
type PeerStore struct {
	mu   sync.RWMutex
	byID map[PeerID]*PeerRecord
	path string // vacío = sólo memoria
}

// NewPeerStore crea un almacén; si path != "" intenta cargar.
func NewPeerStore(path string) *PeerStore {
	s := &PeerStore{byID: make(map[PeerID]*PeerRecord), path: path}
	if path != "" {
		_ = s.Load()
	}
	return s
}

// Upsert inserta o actualiza un registro.
func (s *PeerStore) Upsert(r PeerRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.LastSeen.IsZero() {
		r.LastSeen = time.Now()
	}
	cp := r
	s.byID[r.ID] = &cp
}

// Get recupera por ID.
func (s *PeerStore) Get(id PeerID) (PeerRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.byID[id]
	if !ok {
		return PeerRecord{}, false
	}
	return *r, true
}

// All devuelve una copia de todos los registros.
func (s *PeerStore) All() []PeerRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]PeerRecord, 0, len(s.byID))
	for _, r := range s.byID {
		out = append(out, *r)
	}
	return out
}

// Remove elimina un peer.
func (s *PeerStore) Remove(id PeerID) {
	s.mu.Lock()
	delete(s.byID, id)
	s.mu.Unlock()
}

// Len es el número de peers.
func (s *PeerStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byID)
}

// Save persiste en path (no-op si path vacío).
func (s *PeerStore) Save() error {
	if s.path == "" {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := make([]PeerRecord, 0, len(s.byID))
	for _, r := range s.byID {
		list = append(list, *r)
	}
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0o600)
}

// Load lee desde path.
func (s *PeerStore) Load() error {
	if s.path == "" {
		return nil
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var list []PeerRecord
	if err := json.Unmarshal(data, &list); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range list {
		r := list[i]
		s.byID[r.ID] = &r
	}
	return nil
}
