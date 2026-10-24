package consensus

// Este archivo mantiene el árbol de bloques no finalizados y aplica la
// regla de elección de bifurcación de HotStuff: la punta preferida es el
// bloque certificado por el QC de vista más alta (highQC). Un líder honesto
// siempre propone extendiendo ese bloque, y las reglas de voto
// (round_state.go) impiden que una rama con un QC más bajo reemplace a un
// bloque comprometido.
//
// La raíz del árbol es el último bloque final; al finalizarse un bloque
// nuevo se poda todo lo que no desciende de él (ramas muertas).

import (
	"errors"
	"fmt"
	"sync"

	"github.com/l1/l1/types"
)

// Errores del árbol.
var (
	ErrUnknownBlock     = errors.New("consenso: bloque desconocido")
	ErrNotDescendant    = errors.New("consenso: el bloque no desciende de la raíz")
	ErrInvalidLinkage   = errors.New("consenso: enlace padre-hijo inválido")
	ErrBelowFinalized   = errors.New("consenso: bloque por debajo del finalizado")
	ErrTreeInconsistent = errors.New("consenso: árbol inconsistente")
)

// blockNode es un nodo del árbol.
type blockNode struct {
	block    *types.Block
	parent   *blockNode
	children []*blockNode
	// qc es el QC que certifica a ESTE bloque (si se conoce).
	qc *QuorumCert
}

// view devuelve la vista del bloque.
func (n *blockNode) view() uint64 { return n.block.HeaderRef().View }

// BlockTree es el árbol de bloques pendientes. Seguro para uso concurrente.
type BlockTree struct {
	mu            sync.RWMutex
	nodes         map[types.Hash]*blockNode
	root          *blockNode
	highQC        *QuorumCert
	highCertified *blockNode
}

// NewBlockTree crea el árbol con raíz en el último bloque final y el QC que
// lo certifica (GenesisQC para el génesis).
func NewBlockTree(root *types.Block, rootQC *QuorumCert) *BlockTree {
	n := &blockNode{block: root, qc: rootQC}
	return &BlockTree{nodes: map[types.Hash]*blockNode{root.Hash(): n}, root: n, highQC: rootQC, highCertified: n}
}

// Root devuelve el último bloque final.
func (t *BlockTree) Root() *types.Block { t.mu.RLock(); defer t.mu.RUnlock(); return t.root.block }

// Len es el número de bloques en el árbol (incluida la raíz).
func (t *BlockTree) Len() int { t.mu.RLock(); defer t.mu.RUnlock(); return len(t.nodes) }

// Insert añade un bloque cuyo padre ya esté en el árbol. Es idempotente.
func (t *BlockTree) Insert(b *types.Block) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	h := b.Hash()
	if _, ok := t.nodes[h]; ok {
		return nil
	}
	if b.Number() <= t.root.block.Number() {
		return ErrBelowFinalized
	}
	parent, ok := t.nodes[b.ParentHash()]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownParent, b.ParentHash().Hex())
	}
	if b.Number() != parent.block.Number()+1 || b.HeaderRef().View <= parent.view() {
		return fmt.Errorf("%w: #%d/v%d sobre #%d/v%d", ErrInvalidLinkage, b.Number(), b.HeaderRef().View, parent.block.Number(), parent.view())
	}
	n := &blockNode{block: b, parent: parent}
	parent.children = append(parent.children, n)
	t.nodes[h] = n
	return nil
}

// InsertQC registra el QC de un bloque del árbol y actualiza el highQC.
// Devuelve true si el highQC cambió.
func (t *BlockTree) InsertQC(qc *QuorumCert) (bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	n, ok := t.nodes[qc.BlockHash]
	if !ok {
		return false, fmt.Errorf("%w: %s", ErrUnknownBlock, qc.BlockHash.Hex())
	}
	if n.block.Number() != qc.BlockNumber || n.view() != qc.View {
		return false, fmt.Errorf("%w: el QC no corresponde al bloque", ErrInvalidQC)
	}
	if n.qc == nil {
		n.qc = qc
	}
	if t.highQC == nil || qc.View > t.highQC.View {
		t.highQC, t.highCertified = qc, n
		return true, nil
	}
	return false, nil
}

// Get devuelve un bloque del árbol.
func (t *BlockTree) Get(h types.Hash) (*types.Block, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	n, ok := t.nodes[h]
	if !ok {
		return nil, false
	}
	return n.block, true
}

// Contains informa si el bloque está en el árbol.
func (t *BlockTree) Contains(h types.Hash) bool { _, ok := t.Get(h); return ok }

// QCFor devuelve el QC que certifica al bloque (nil si no se conoce).
func (t *BlockTree) QCFor(h types.Hash) *QuorumCert {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if n, ok := t.nodes[h]; ok {
		return n.qc
	}
	return nil
}

// Parent devuelve el padre de un bloque del árbol.
func (t *BlockTree) Parent(h types.Hash) (*types.Block, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	n, ok := t.nodes[h]
	if !ok || n.parent == nil {
		return nil, false
	}
	return n.parent.block, true
}

// HighQC devuelve el QC de vista más alta.
func (t *BlockTree) HighQC() *QuorumCert { t.mu.RLock(); defer t.mu.RUnlock(); return t.highQC }

// PreferredHead devuelve el bloque que debe extender la próxima propuesta:
// el certificado por el highQC.
func (t *BlockTree) PreferredHead() *types.Block {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.highCertified.block
}

// IsAncestor informa si anc es ancestro (o igual) de desc.
func (t *BlockTree) IsAncestor(anc, desc types.Hash) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	for n := t.nodes[desc]; n != nil; n = n.parent {
		if n.block.Hash() == anc {
			return true
		}
	}
	return false
}

// PathFromRoot devuelve los bloques desde el hijo de la raíz hasta h, en
// orden ascendente.
func (t *BlockTree) PathFromRoot(h types.Hash) ([]*types.Block, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.pathLocked(h)
}

// pathLocked implementa PathFromRoot con el cerrojo tomado.
func (t *BlockTree) pathLocked(h types.Hash) ([]*types.Block, error) {
	n, ok := t.nodes[h]
	if !ok {
		return nil, ErrUnknownBlock
	}
	var rev []*types.Block
	for ; n != t.root; n = n.parent {
		if n == nil {
			return nil, ErrTreeInconsistent
		}
		rev = append(rev, n.block)
	}
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	return rev, nil
}

// Prune convierte h (descendiente de la raíz) en la nueva raíz y elimina
// todos los bloques que no descienden de ella. Devuelve los hashes podados
// (ramas muertas, no los ancestros finalizados).
func (t *BlockTree) Prune(h types.Hash) ([]types.Hash, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	newRoot, ok := t.nodes[h]
	if !ok {
		return nil, ErrUnknownBlock
	}
	if newRoot == t.root {
		return nil, nil
	}
	if _, err := t.pathLocked(h); err != nil {
		return nil, ErrNotDescendant
	}
	// Conservamos el subárbol de newRoot.
	keep := map[types.Hash]*blockNode{}
	stack := []*blockNode{newRoot}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		keep[n.block.Hash()] = n
		stack = append(stack, n.children...)
	}
	// Los ancestros de newRoot se finalizan; el resto se poda.
	ancestors := map[types.Hash]bool{}
	for n := newRoot.parent; n != nil; n = n.parent {
		ancestors[n.block.Hash()] = true
	}
	var pruned []types.Hash
	for hh := range t.nodes {
		if _, k := keep[hh]; !k && !ancestors[hh] {
			pruned = append(pruned, hh)
		}
	}
	t.nodes = keep
	newRoot.parent = nil
	t.root = newRoot
	if _, ok := keep[t.highCertified.block.Hash()]; !ok {
		// No debería ocurrir (el highQC desciende del finalizado), pero el
		// árbol queda coherente apuntando a la nueva raíz.
		t.highCertified = newRoot
		if newRoot.qc != nil {
			t.highQC = newRoot.qc
		}
	}
	return pruned, nil
}

// Leaves devuelve las puntas del árbol (bloques sin hijos).
func (t *BlockTree) Leaves() []*types.Block {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var out []*types.Block
	for _, n := range t.nodes {
		if len(n.children) == 0 {
			out = append(out, n.block)
		}
	}
	return out
}
