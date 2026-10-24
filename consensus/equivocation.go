package consensus

// Detección y empaquetado de equivocaciones (doble voto / doble propuesta).
// Las evidencias se difunden por la red y se aplican vía el contrato de
// slashing (slashing.go).

import (
	"fmt"

	"github.com/l1/l1/crypto"
	"github.com/l1/l1/types"
)

// EquivocationTracker recuerda el último voto/propuesta por validador y
// vista para detectar conflictos en caliente.
type EquivocationTracker struct {
	votes     map[voteKey]*Vote
	proposals map[ProposalKey]*Proposal
	chainID   types.ChainID
}

type voteKey struct {
	voter types.Address
	view  uint64
}

// NewEquivocationTracker crea un rastreador vacío.
func NewEquivocationTracker(chainID types.ChainID) *EquivocationTracker {
	return &EquivocationTracker{
		votes:     make(map[voteKey]*Vote),
		proposals: make(map[ProposalKey]*Proposal),
		chainID:   chainID,
	}
}

// ObserveVote registra un voto. Si choca con uno previo de la misma vista,
// construye DoubleVoteEvidence.
func (t *EquivocationTracker) ObserveVote(v *Vote) (*DoubleVoteEvidence, error) {
	if v == nil {
		return nil, nil
	}
	k := voteKey{voter: v.Voter, view: v.View}
	prev, ok := t.votes[k]
	if !ok {
		t.votes[k] = v
		return nil, nil
	}
	if prev.BlockHash == v.BlockHash {
		return nil, nil // mismo voto, idempotente
	}
	ev := &DoubleVoteEvidence{A: prev, B: v}
	if err := ev.ValidateBasic(); err != nil {
		return nil, err
	}
	return ev, nil
}

// ObserveProposal registra una propuesta. Dos propuestas distintas del
// mismo líder en la misma vista son equivocación de propuesta (se reporta
// como error; el slashing on-chain cubre votos).
func (t *EquivocationTracker) ObserveProposal(p *Proposal) error {
	if p == nil {
		return nil
	}
	k := p.Key()
	prev, ok := t.proposals[k]
	if !ok {
		t.proposals[k] = p
		return nil
	}
	if prev.Block.Hash() == p.Block.Hash() {
		return nil
	}
	return fmt.Errorf("%w: líder %s vista %d", ErrInvalidEvidence, p.Proposer().Hex(), p.View())
}

// Prune elimina entradas por debajo de minView.
func (t *EquivocationTracker) Prune(minView uint64) {
	for k := range t.votes {
		if k.view < minView {
			delete(t.votes, k)
		}
	}
	for k := range t.proposals {
		if k.View < minView {
			delete(t.proposals, k)
		}
	}
}

// VerifyEvidence comprueba una evidencia con la clave pública del ofensor.
func VerifyEvidence(ev *DoubleVoteEvidence, pk *crypto.BLSPublicKey, chainID types.ChainID) error {
	if ev == nil {
		return ErrInvalidEvidence
	}
	return ev.Verify(pk, chainID)
}
