package consensus

// Este archivo aplica la regla de compromiso de DOS cadenas: cuando se
// conoce un QC para el bloque B' y su padre B fue propuesto en la vista
// inmediatamente anterior (vista(B') = vista(B) + 1), B y todos sus
// ancestros no finalizados son FINALES.
//
// Intuición de seguridad: el QC de B' prueba que 2f+1 validadores votaron
// B' y, por tanto, adoptaron QC(B) como highQC en la vista v+1. Cualquier
// TC posterior incluye al menos un honesto de ese grupo, así que su
// max(highQC) >= v y las reglas de voto obligan a extender B. Ningún bloque
// en conflicto con B puede reunir un QC.
//
// La exigencia de vistas consecutivas es clave: si entre B y B' hubo un
// timeout, el QC de B pudo no estar en manos de 2f+1 y B aún podría ser
// abandonado.

import (
	"sync"

	"github.com/l1/l1/types"
)

// TwoChainCommit informa si la pareja (padre, hijo certificado) compromete
// al padre.
func TwoChainCommit(parent, child *types.Header) bool {
	return child.ParentHash == parent.Hash() && child.View == parent.View+1
}

// FinalityTracker observa QCs y emite los bloques que se vuelven finales.
type FinalityTracker struct {
	mu        sync.Mutex
	tree      *BlockTree
	finalized *types.Block
	onCommit  CommitHandler
}

// NewFinalityTracker crea el rastreador sobre el árbol (cuya raíz se
// considera final). onCommit puede ser nil.
func NewFinalityTracker(tree *BlockTree, onCommit CommitHandler) *FinalityTracker {
	return &FinalityTracker{tree: tree, finalized: tree.Root(), onCommit: onCommit}
}

// Finalized devuelve el último bloque final.
func (f *FinalityTracker) Finalized() *types.Block {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.finalized
}

// IsFinalized informa si una altura ya es final.
func (f *FinalityTracker) IsFinalized(number uint64) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return number <= f.finalized.Number()
}

// ProcessQC registra un QC (cuyo bloque debe estar en el árbol) y, si se
// cumple la regla de dos cadenas, finaliza al padre del bloque certificado.
// Devuelve los bloques recién finalizados en orden ascendente.
func (f *FinalityTracker) ProcessQC(qc *QuorumCert) ([]*types.Block, error) {
	if _, err := f.tree.InsertQC(qc); err != nil {
		return nil, err
	}
	f.mu.Lock()
	child, ok := f.tree.Get(qc.BlockHash)
	if !ok {
		f.mu.Unlock()
		return nil, ErrUnknownBlock
	}
	parent, ok := f.tree.Parent(qc.BlockHash)
	if !ok || parent.Number() <= f.finalized.Number() || !TwoChainCommit(parent.HeaderRef(), child.HeaderRef()) {
		f.mu.Unlock()
		return nil, nil
	}
	blocks, err := f.tree.PathFromRoot(parent.Hash())
	if err != nil {
		f.mu.Unlock()
		return nil, err
	}
	if _, err := f.tree.Prune(parent.Hash()); err != nil {
		f.mu.Unlock()
		return nil, err
	}
	f.finalized = parent
	cb := f.onCommit
	f.mu.Unlock()
	if cb != nil && len(blocks) > 0 {
		cb(blocks, qc)
	}
	return blocks, nil
}
