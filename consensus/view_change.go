package consensus

// Este archivo implementa el cambio de vista por timeout: el colector de
// TimeoutMsg que forma TCs y la regla de "sumarse" (amplificación al estilo
// Bracha): si un validador ve timeouts de f+1 de poder para una vista en
// la que sigue, al menos un honesto ya la abandonó, así que se suma
// enviando su propio timeout sin esperar a su temporizador. Esto garantiza
// que, si un honesto agota el tiempo, todos acaban formando el TC aunque
// sus relojes difieran.

import (
	"fmt"
	"sync"

	"github.com/l1/l1/crypto"
	"github.com/l1/l1/types"
)

// timeoutBucket acumula los timeouts de una vista.
type timeoutBucket struct {
	msgs   map[types.Address]*TimeoutMsg
	power  uint64
	tc     *TimeoutCert
	joined bool
}

// TimeoutCollector agrupa timeouts por vista. Seguro para uso concurrente.
type TimeoutCollector struct {
	mu      sync.Mutex
	chainID types.ChainID
	epoch   uint64
	set     *ValidatorSet
	sets    ValidatorSetProvider
	views   map[uint64]*timeoutBucket
}

// NewTimeoutCollector crea un colector para una época. sets resuelve el
// conjunto de la época de cada highQC (que puede ser anterior).
func NewTimeoutCollector(chainID types.ChainID, epoch uint64, set *ValidatorSet, sets ValidatorSetProvider) *TimeoutCollector {
	return &TimeoutCollector{chainID: chainID, epoch: epoch, set: set, sets: sets, views: map[uint64]*timeoutBucket{}}
}

// TimeoutResult es el efecto de añadir un timeout.
type TimeoutResult struct {
	// TC se rellena la primera vez que la vista alcanza quórum.
	TC *TimeoutCert
	// Join indica que se acaba de alcanzar f+1 de poder: el llamante
	// debería emitir su propio timeout para esa vista si aún no lo hizo.
	Join bool
	// HighQC es el QC adjunto al timeout (útil para actualizar el highQC
	// local aunque no se forme TC).
	HighQC *QuorumCert
}

// Add verifica e incorpora un timeout.
func (c *TimeoutCollector) Add(t *TimeoutMsg) (TimeoutResult, error) {
	if t.Epoch != c.epoch {
		return TimeoutResult{}, fmt.Errorf("%w: %d != %d", ErrWrongEpoch, t.Epoch, c.epoch)
	}
	if err := t.Verify(c.set, c.sets, c.chainID); err != nil {
		return TimeoutResult{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	b := c.views[t.View]
	if b == nil {
		b = &timeoutBucket{msgs: map[types.Address]*TimeoutMsg{}}
		c.views[t.View] = b
	}
	if _, dup := b.msgs[t.Sender]; dup {
		return TimeoutResult{}, ErrDuplicateVote
	}
	_, val := c.set.ByAddress(t.Sender)
	b.msgs[t.Sender] = t
	b.power += val.Power
	res := TimeoutResult{HighQC: t.HighQC}
	if !b.joined && b.power >= c.set.ValidityPower() {
		b.joined = true
		res.Join = true
	}
	if b.tc == nil && c.set.HasQuorum(b.power) {
		tc, err := c.buildTC(t.View, b)
		if err != nil {
			return res, err
		}
		b.tc = tc
		res.TC = tc
	}
	return res, nil
}

// buildTC agrega los timeouts de una vista en un TC.
func (c *TimeoutCollector) buildTC(view uint64, b *timeoutBucket) (*TimeoutCert, error) {
	bm := NewBitmap(c.set.Size())
	for a := range b.msgs {
		i, _ := c.set.ByAddress(a)
		bm.Set(i)
	}
	tc := &TimeoutCert{Epoch: c.epoch, View: view, Signers: bm}
	sigs := make([]*crypto.BLSSignature, 0, len(b.msgs))
	for _, i := range bm.Indices() {
		m := b.msgs[c.set.ByIndex(i).Address]
		s, err := crypto.BLSSignatureFromBytes(m.Signature)
		if err != nil {
			return nil, err
		}
		sigs = append(sigs, s)
		tc.HighQCViews = append(tc.HighQCViews, m.HighQC.View)
		if tc.HighQC == nil || m.HighQC.View > tc.HighQC.View {
			tc.HighQC = m.HighQC
		}
	}
	agg, err := crypto.AggregateSignatures(sigs)
	if err != nil {
		return nil, err
	}
	tc.Signature = agg.Bytes()
	return tc, nil
}

// Power devuelve el poder acumulado de timeouts para una vista.
func (c *TimeoutCollector) Power(view uint64) uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if b := c.views[view]; b != nil {
		return b.power
	}
	return 0
}

// Prune descarta vistas inferiores a minView.
func (c *TimeoutCollector) Prune(minView uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for v := range c.views {
		if v < minView {
			delete(c.views, v)
		}
	}
}

// NextView calcula la vista a la que se debe avanzar dados el QC y el TC más
// altos conocidos: una más que la mayor de sus vistas.
func NextView(qc *QuorumCert, tc *TimeoutCert) uint64 {
	var v uint64
	if qc != nil {
		v = qc.View
	}
	if tc != nil && tc.View > v {
		v = tc.View
	}
	return v + 1
}
