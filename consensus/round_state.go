package consensus

// Este archivo guarda el estado de la ronda (vista) en curso de un
// validador y aplica las reglas de seguridad de voto del protocolo de dos
// cadenas (Jolteon):
//
//   - Nunca se vota dos veces en la misma vista, ni en una vista ya
//     abandonada por timeout: LastVotedView sólo crece.
//   - Se vota una propuesta de la vista v si su QC es de v-1 (camino feliz)
//     o si trae un TC de v-1 y su QC es de vista >= max(highQC del TC).
//     Esta segunda condición impide que un líder, tras un timeout, "salte"
//     un bloque que pudiera estar ya comprometido.
//   - Se emite timeout para v sólo si v >= LastVotedView (y después ya no
//     se vota en v).
//
// La persistencia de estas variables (para no violarlas tras reiniciar) es
// responsabilidad de las reglas de seguridad del día 11 (safety_rules.go);
// aquí se exponen Snapshot/Restore para ello.

import (
	"errors"
	"fmt"
	"sync"
)

// Errores de reglas de voto.
var (
	ErrAlreadyVoted  = errors.New("consenso: ya se votó en esta vista o una posterior")
	ErrUnsafeVote    = errors.New("consenso: voto inseguro")
	ErrWrongView     = errors.New("consenso: vista distinta de la actual")
	ErrUnsafeTimeout = errors.New("consenso: timeout inseguro")
)

// Step es la fase dentro de una vista.
type Step uint8

// Fases de una vista.
const (
	StepNewView  Step = iota // esperando propuesta
	StepProposed             // propuesta recibida y validada
	StepVoted                // voto emitido
	StepTimedOut             // timeout emitido
)

// String devuelve el nombre de la fase.
func (s Step) String() string {
	switch s {
	case StepNewView:
		return "nueva-vista"
	case StepProposed:
		return "propuesta"
	case StepVoted:
		return "votado"
	case StepTimedOut:
		return "timeout"
	}
	return "?"
}

// RoundSnapshot son las variables persistibles.
type RoundSnapshot struct {
	Epoch         uint64
	View          uint64
	LastVotedView uint64
	HighQCView    uint64
}

// RoundState es el estado de la ronda. Seguro para uso concurrente.
type RoundState struct {
	mu            sync.Mutex
	epoch         uint64
	view          uint64
	step          Step
	proposal      *Proposal
	lastVotedView uint64
	highQC        *QuorumCert
	highTC        *TimeoutCert
}

// NewRoundState crea el estado a partir del highQC conocido.
func NewRoundState(epoch uint64, highQC *QuorumCert) *RoundState {
	return &RoundState{epoch: epoch, view: NextView(highQC, nil), highQC: highQC}
}

// Restore aplica un snapshot persistido (sólo puede subir las cotas).
func (r *RoundState) Restore(s RoundSnapshot) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s.LastVotedView > r.lastVotedView {
		r.lastVotedView = s.LastVotedView
	}
	if s.View > r.view {
		r.view, r.epoch = s.View, s.Epoch
	}
}

// Snapshot devuelve las variables persistibles.
func (r *RoundState) Snapshot() RoundSnapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := RoundSnapshot{Epoch: r.epoch, View: r.view, LastVotedView: r.lastVotedView}
	if r.highQC != nil {
		s.HighQCView = r.highQC.View
	}
	return s
}

// EnterView pasa a una vista nueva (ignora retrocesos).
func (r *RoundState) EnterView(epoch, view uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Se permite "re-entrar" en la vista actual sólo si aún no se hizo nada
	// en ella (p. ej. para fijar la época tras construir el estado).
	if view < r.view || (view == r.view && r.step != StepNewView) {
		return false
	}
	r.epoch, r.view, r.step, r.proposal = epoch, view, StepNewView, nil
	return true
}

// View devuelve época y vista actuales.
func (r *RoundState) View() (epoch, view uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.epoch, r.view
}

// Step devuelve la fase actual.
func (r *RoundState) Step() Step { r.mu.Lock(); defer r.mu.Unlock(); return r.step }

// Proposal devuelve la propuesta aceptada en la vista actual.
func (r *RoundState) Proposal() *Proposal { r.mu.Lock(); defer r.mu.Unlock(); return r.proposal }

// LastVotedView devuelve la mayor vista votada o abandonada.
func (r *RoundState) LastVotedView() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastVotedView
}

// HighQC devuelve el QC más alto conocido.
func (r *RoundState) HighQC() *QuorumCert { r.mu.Lock(); defer r.mu.Unlock(); return r.highQC }

// HighTC devuelve el TC más alto conocido.
func (r *RoundState) HighTC() *TimeoutCert { r.mu.Lock(); defer r.mu.Unlock(); return r.highTC }

// UpdateHighQC adopta qc si es más alto. Devuelve true si cambió.
func (r *RoundState) UpdateHighQC(qc *QuorumCert) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if qc == nil || (r.highQC != nil && qc.View <= r.highQC.View) {
		return false
	}
	r.highQC = qc
	return true
}

// UpdateHighTC adopta tc si es más alto (y su highQC).
func (r *RoundState) UpdateHighTC(tc *TimeoutCert) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if tc == nil || (r.highTC != nil && tc.View <= r.highTC.View) {
		return false
	}
	r.highTC = tc
	if tc.HighQC != nil && (r.highQC == nil || tc.HighQC.View > r.highQC.View) {
		r.highQC = tc.HighQC
	}
	return true
}

// CheckVoteRule aplica las reglas de voto a una propuesta ya validada
// (firmas, líder, bloque) con su QC decodificado. No modifica el estado.
func CheckVoteRule(lastVotedView uint64, p *Proposal, qc *QuorumCert) error {
	v := p.View()
	if v <= lastVotedView {
		return fmt.Errorf("%w: vista %d <= %d", ErrAlreadyVoted, v, lastVotedView)
	}
	if qc.View+1 == v {
		return nil
	}
	if p.TC != nil && p.TC.View+1 == v && qc.View >= p.TC.MaxHighQCView() {
		return nil
	}
	return fmt.Errorf("%w: QC de vista %d no justifica la vista %d", ErrUnsafeVote, qc.View, v)
}

// AcceptProposal registra la propuesta de la vista actual tras comprobar
// las reglas de voto.
func (r *RoundState) AcceptProposal(p *Proposal, qc *QuorumCert) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if p.View() != r.view {
		return fmt.Errorf("%w: %d != %d", ErrWrongView, p.View(), r.view)
	}
	if err := CheckVoteRule(r.lastVotedView, p, qc); err != nil {
		return err
	}
	r.proposal, r.step = p, StepProposed
	return nil
}

// RecordVote marca que se votó en la vista actual; falla si ya no es
// seguro (p. ej. porque entretanto se emitió un timeout).
func (r *RoundState) RecordVote(view uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if view <= r.lastVotedView {
		return ErrAlreadyVoted
	}
	r.lastVotedView, r.step = view, StepVoted
	return nil
}

// RecordTimeout marca que se abandona la vista (y ya no se votará en ella).
func (r *RoundState) RecordTimeout(view uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if view < r.lastVotedView {
		return fmt.Errorf("%w: vista %d < %d", ErrUnsafeTimeout, view, r.lastVotedView)
	}
	r.lastVotedView = view
	if view == r.view {
		r.step = StepTimedOut
	}
	return nil
}
