package p2p

// Puntuación de peers: recompensa comportamiento útil (bloques válidos,
// respuestas a sync) y penaliza spam/invalidaciones. Alimenta la ban-list.

import (
	"sync"
	"time"
)

// ScoreConfig umbrales de puntuación.
type ScoreConfig struct {
	BanBelow        float64 // por debajo → ban
	DisconnectBelow float64
	MaxScore        float64
	DecayPerHour    float64
}

// DefaultScoreConfig valores razonables.
func DefaultScoreConfig() ScoreConfig {
	return ScoreConfig{BanBelow: -50, DisconnectBelow: -20, MaxScore: 100, DecayPerHour: 1}
}

// Scorer mantiene puntuaciones en memoria.
type Scorer struct {
	mu   sync.Mutex
	cfg  ScoreConfig
	sc   map[PeerID]float64
	when map[PeerID]time.Time
}

// NewScorer crea un scorer.
func NewScorer(cfg ScoreConfig) *Scorer {
	return &Scorer{cfg: cfg, sc: make(map[PeerID]float64), when: make(map[PeerID]time.Time)}
}

// Add suma delta (positivo o negativo) y aplica decay.
func (s *Scorer) Add(id PeerID, delta float64) float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.decayLocked(id)
	v := s.sc[id] + delta
	if v > s.cfg.MaxScore {
		v = s.cfg.MaxScore
	}
	s.sc[id] = v
	s.when[id] = time.Now()
	return v
}

// Score consulta la puntuación actual (con decay).
func (s *Scorer) Score(id PeerID) float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.decayLocked(id)
	return s.sc[id]
}

// ShouldBan indica si el peer debe banearse.
func (s *Scorer) ShouldBan(id PeerID) bool { return s.Score(id) <= s.cfg.BanBelow }

// ShouldDisconnect indica desconexión suave.
func (s *Scorer) ShouldDisconnect(id PeerID) bool {
	return s.Score(id) <= s.cfg.DisconnectBelow
}

func (s *Scorer) decayLocked(id PeerID) {
	last, ok := s.when[id]
	if !ok {
		return
	}
	hours := time.Since(last).Hours()
	if hours <= 0 {
		return
	}
	v := s.sc[id]
	if v < 0 {
		v += s.cfg.DecayPerHour * hours
		if v > 0 {
			v = 0
		}
	} else if v > 0 {
		v -= s.cfg.DecayPerHour * hours
		if v < 0 {
			v = 0
		}
	}
	s.sc[id] = v
	s.when[id] = time.Now()
}

// Constantes de deltas habituales.
const (
	ScoreValidBlock   = 1.0
	ScoreValidTx      = 0.1
	ScoreInvalidMsg   = -5.0
	ScoreProtocolErr  = -10.0
	ScoreTimeout      = -2.0
	ScoreGoodResponse = 0.5
)
