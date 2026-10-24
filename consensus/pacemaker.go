package consensus

// Este archivo implementa el pacemaker: el componente que decide en qué
// vista está el validador y cuándo darla por perdida. Reglas:
//
//   - Al conocer un QC de la vista v (o mayor que la actual), se avanza a
//     v+1 y se reinicia el contador de timeouts consecutivos (la red
//     progresa, así que la duración vuelve a la base).
//   - Al conocer un TC de la vista v, se avanza a v+1 incrementando el
//     contador: la siguiente vista dura más (backoff exponencial).
//   - Si el temporizador de la vista vence, se invoca OnTimeout (el motor
//     firma y difunde un TimeoutMsg) y se rearma con la misma duración para
//     re-difundir periódicamente hasta que llegue un QC o TC: la vista NO
//     cambia por el mero vencimiento local.
//
// El reloj se abstrae (Clock) para poder probar el pacemaker de forma
// determinista.

import (
	"sync"
	"time"
)

// Stopper detiene un temporizador.
type Stopper interface{ Stop() bool }

// Clock abstrae el tiempo.
type Clock interface {
	Now() time.Time
	AfterFunc(d time.Duration, f func()) Stopper
}

// realClock usa el paquete time.
type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }
func (realClock) AfterFunc(d time.Duration, f func()) Stopper {
	return time.AfterFunc(d, f)
}

// RealClock devuelve el reloj del sistema.
func RealClock() Clock { return realClock{} }

// ViewChangeReason explica por qué cambió la vista.
type ViewChangeReason uint8

// Motivos de cambio de vista.
const (
	ReasonStart ViewChangeReason = iota
	ReasonQC
	ReasonTC
)

// String devuelve el nombre del motivo.
func (r ViewChangeReason) String() string {
	switch r {
	case ReasonStart:
		return "inicio"
	case ReasonQC:
		return "QC"
	case ReasonTC:
		return "TC"
	}
	return "?"
}

// Pacemaker gestiona la vista actual y sus temporizadores. Es seguro para
// uso concurrente; los callbacks se invocan sin el cerrojo tomado.
type Pacemaker struct {
	mu          sync.Mutex
	cfg         TimeoutConfig
	clock       Clock
	view        uint64
	highQC      *QuorumCert
	highTC      *TimeoutCert
	consecutive int
	timer       Stopper
	gen         uint64 // generación del temporizador (descarta disparos viejos)
	attempts    int
	running     bool
	viewStart   time.Time

	// OnTimeout se invoca al vencer el temporizador de una vista (attempt
	// cuenta los vencimientos en esa misma vista, desde 1).
	OnTimeout func(view uint64, attempt int)
	// OnNewView se invoca al entrar en una vista nueva.
	OnNewView func(view uint64, reason ViewChangeReason)
}

// NewPacemaker crea un pacemaker en la vista siguiente a highQC.
func NewPacemaker(cfg TimeoutConfig, clock Clock, highQC *QuorumCert) *Pacemaker {
	if clock == nil {
		clock = RealClock()
	}
	p := &Pacemaker{cfg: cfg, clock: clock, highQC: highQC}
	p.view = NextView(highQC, nil)
	return p
}

// Start arma el temporizador de la vista actual.
func (p *Pacemaker) Start() {
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		return
	}
	p.running = true
	p.resetTimerLocked()
	view, cb := p.view, p.OnNewView
	p.mu.Unlock()
	if cb != nil {
		cb(view, ReasonStart)
	}
}

// Stop detiene el temporizador.
func (p *Pacemaker) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.running = false
	p.gen++
	if p.timer != nil {
		p.timer.Stop()
		p.timer = nil
	}
}

// View devuelve la vista actual.
func (p *Pacemaker) View() uint64 { p.mu.Lock(); defer p.mu.Unlock(); return p.view }

// HighQC devuelve el QC más alto conocido.
func (p *Pacemaker) HighQC() *QuorumCert { p.mu.Lock(); defer p.mu.Unlock(); return p.highQC }

// HighTC devuelve el TC más alto conocido.
func (p *Pacemaker) HighTC() *TimeoutCert { p.mu.Lock(); defer p.mu.Unlock(); return p.highTC }

// ConsecutiveTimeouts devuelve el contador de backoff.
func (p *Pacemaker) ConsecutiveTimeouts() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.consecutive
}

// CurrentTimeout devuelve la duración de la vista actual.
func (p *Pacemaker) CurrentTimeout() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cfg.Duration(p.consecutive)
}

// ViewElapsed devuelve cuánto lleva la vista actual.
func (p *Pacemaker) ViewElapsed() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.clock.Now().Sub(p.viewStart)
}

// ProcessQC incorpora un QC. Devuelve true si provocó un cambio de vista.
func (p *Pacemaker) ProcessQC(qc *QuorumCert) bool {
	if qc == nil {
		return false
	}
	p.mu.Lock()
	if p.highQC == nil || qc.View > p.highQC.View {
		p.highQC = qc
	}
	if qc.View < p.view {
		p.mu.Unlock()
		return false
	}
	p.consecutive = 0
	return p.advanceLocked(qc.View+1, ReasonQC)
}

// ProcessTC incorpora un TC. Devuelve true si provocó un cambio de vista.
func (p *Pacemaker) ProcessTC(tc *TimeoutCert) bool {
	if tc == nil {
		return false
	}
	p.mu.Lock()
	if tc.HighQC != nil && (p.highQC == nil || tc.HighQC.View > p.highQC.View) {
		p.highQC = tc.HighQC
	}
	if p.highTC == nil || tc.View > p.highTC.View {
		p.highTC = tc
	}
	if tc.View < p.view {
		p.mu.Unlock()
		return false
	}
	p.consecutive++
	return p.advanceLocked(tc.View+1, ReasonTC)
}

// advanceLocked entra en la vista v (con el cerrojo tomado; lo libera).
func (p *Pacemaker) advanceLocked(v uint64, reason ViewChangeReason) bool {
	p.view = v
	if p.running {
		p.resetTimerLocked()
	}
	cb := p.OnNewView
	p.mu.Unlock()
	if cb != nil {
		cb(v, reason)
	}
	return true
}

// resetTimerLocked arma el temporizador de la vista actual.
func (p *Pacemaker) resetTimerLocked() {
	if p.timer != nil {
		p.timer.Stop()
	}
	p.gen++
	p.attempts = 0
	p.viewStart = p.clock.Now()
	p.armLocked()
}

// armLocked programa el siguiente vencimiento de la generación actual.
func (p *Pacemaker) armLocked() {
	gen := p.gen
	p.timer = p.clock.AfterFunc(p.cfg.Duration(p.consecutive), func() { p.fire(gen) })
}

// fire maneja el vencimiento del temporizador.
func (p *Pacemaker) fire(gen uint64) {
	p.mu.Lock()
	if !p.running || gen != p.gen {
		p.mu.Unlock()
		return
	}
	p.attempts++
	view, attempt, cb := p.view, p.attempts, p.OnTimeout
	p.armLocked() // re-difusión periódica hasta que haya QC o TC
	p.mu.Unlock()
	if cb != nil {
		cb(view, attempt)
	}
}

// forceView salta a la vista v sin QC/TC (reinicio tras WAL). No invoca
// OnNewView: el arranque posterior de Start() rearmará el temporizador y
// el primer tick de nueva vista lo disparará ProcessQC o Start mismo.
func (p *Pacemaker) forceView(v uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if v <= p.view {
		return
	}
	p.view = v
	p.consecutive = 0
}
