package consensus

// Reglas de seguridad HotStuff: un nodo nunca vota dos veces en la misma
// vista ni por debajo de su highQC (locked QC). SafetyRules combina el
// RoundState con el WAL para garantizar que, tras un reinicio, las
// promesas se conservan.

import "fmt"

// SafetyRules aplica CheckVoteRule y persiste el snapshot antes de votar.
type SafetyRules struct {
	round *RoundState
	wal   *ConsensusWAL
}

// NewSafetyRules crea el envoltorio. wal puede ser nil (sólo memoria).
func NewSafetyRules(round *RoundState, wal *ConsensusWAL) *SafetyRules {
	return &SafetyRules{round: round, wal: wal}
}

// RestoreFromWAL carga el último snapshot si existe.
func (s *SafetyRules) RestoreFromWAL() error {
	if s.wal == nil {
		return nil
	}
	snap, err := s.wal.LoadLast()
	if err == ErrWALMissing {
		return nil
	}
	if err != nil {
		return err
	}
	s.round.Restore(snap)
	return nil
}

// MayVote comprueba la regla de voto sin mutar estado.
func (s *SafetyRules) MayVote(p *Proposal, qc *QuorumCert) error {
	return CheckVoteRule(s.round.LastVotedView(), p, qc)
}

// CommitVote acepta la propuesta, registra el voto y persiste.
func (s *SafetyRules) CommitVote(p *Proposal, qc *QuorumCert) error {
	if err := s.round.AcceptProposal(p, qc); err != nil {
		return err
	}
	if err := s.round.RecordVote(p.View()); err != nil {
		return err
	}
	return s.persist()
}

// CommitTimeout registra un timeout seguro y persiste.
func (s *SafetyRules) CommitTimeout(view uint64) error {
	if err := s.round.RecordTimeout(view); err != nil {
		return err
	}
	return s.persist()
}

func (s *SafetyRules) persist() error {
	if s.wal == nil {
		return nil
	}
	if err := s.wal.Persist(s.round.Snapshot()); err != nil {
		return fmt.Errorf("consenso: persistir seguridad: %w", err)
	}
	return nil
}

// Round expone el RoundState subyacente.
func (s *SafetyRules) Round() *RoundState { return s.round }
