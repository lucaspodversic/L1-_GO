package mempool

// Este archivo implementa las dos políticas de desalojo del pool:
//
//  1. Por precio (pricedList): cuando el pool está lleno, una tx remota
//     nueva sólo entra si paga más que la más barata del pool, que se
//     desaloja. "Barata" se mide por la propina efectiva con la base fee
//     del siguiente bloque (y, a igualdad, por feeCap). Las transacciones
//     locales nunca se desalojan por precio.
//  2. Por antigüedad (evictStale): las colas futuras de cuentas remotas
//     sin actividad durante Lifetime se descartan, porque probablemente
//     nunca serán ejecutables.
//
// El montículo usa borrado perezoso: las txs que salen del pool por otras
// vías quedan "rancias" en el montículo y se saltan al extraer; cuando
// hay demasiadas se reconstruye.

import (
	"container/heap"
	"time"

	"github.com/l1/l1/types"
)

// priceHeap es un min-heap por atractivo para el proponente.
type priceHeap struct {
	baseFee types.Amount
	list    []*types.Transaction
}

func (h *priceHeap) Len() int      { return len(h.list) }
func (h *priceHeap) Swap(i, j int) { h.list[i], h.list[j] = h.list[j], h.list[i] }
func (h *priceHeap) Less(i, j int) bool {
	switch c := h.cmp(h.list[i], h.list[j]); c {
	case -1:
		return true
	case 1:
		return false
	}
	// Desempate: nonce mayor primero (es la que menos rompe la cuenta).
	return h.list[i].Nonce > h.list[j].Nonce
}

// cmp compara a y b: -1 si a es más barata.
func (h *priceHeap) cmp(a, b *types.Transaction) int {
	ta, oka := EffectiveTip(a, h.baseFee)
	tb, okb := EffectiveTip(b, h.baseFee)
	switch {
	case !oka && okb:
		return -1
	case oka && !okb:
		return 1
	}
	if c := ta.Cmp(tb); c != 0 {
		return c
	}
	if c := a.GasFeeCap.Cmp(b.GasFeeCap); c != 0 {
		return c
	}
	return a.GasTipCap.Cmp(b.GasTipCap)
}
func (h *priceHeap) Push(x any) { h.list = append(h.list, x.(*types.Transaction)) }
func (h *priceHeap) Pop() any {
	old := h.list
	x := old[len(old)-1]
	h.list = old[:len(old)-1]
	return x
}

// pricedList ordena las transacciones remotas por precio.
type pricedList struct {
	all    *txLookup
	heap   priceHeap
	stales int
}

// newPricedList crea la lista sobre el índice del pool.
func newPricedList(all *txLookup) *pricedList { return &pricedList{all: all} }

// Put añade una tx remota.
func (p *pricedList) Put(tx *types.Transaction, local bool) {
	if local {
		return
	}
	heap.Push(&p.heap, tx)
}

// Removed anota n borrados perezosos y reconstruye si conviene.
func (p *pricedList) Removed(n int) {
	p.stales += n
	if p.stales > len(p.heap.list)/4 {
		p.Reheap()
	}
}

// isStale informa si tx ya no está en el pool.
func (p *pricedList) isStale(tx *types.Transaction) bool { return p.all.GetRemote(tx.Hash()) == nil }

// Underpriced informa si tx es igual o más barata que la más barata.
func (p *pricedList) Underpriced(tx *types.Transaction) bool {
	for len(p.heap.list) > 0 {
		head := p.heap.list[0]
		if p.isStale(head) {
			heap.Pop(&p.heap)
			p.stales--
			continue
		}
		return p.heap.cmp(head, tx) >= 0
	}
	return false
}

// Discard extrae hasta n de las más baratas (siguen en el pool: el
// llamador las elimina).
func (p *pricedList) Discard(n int) []*types.Transaction {
	drop := make([]*types.Transaction, 0, n)
	for len(drop) < n && len(p.heap.list) > 0 {
		tx := heap.Pop(&p.heap).(*types.Transaction)
		if p.isStale(tx) {
			p.stales--
			continue
		}
		drop = append(drop, tx)
	}
	return drop
}

// SetBaseFee cambia la base fee de referencia y reordena.
func (p *pricedList) SetBaseFee(baseFee types.Amount) {
	p.heap.baseFee = baseFee
	p.Reheap()
}

// Reheap reconstruye el montículo desde el índice.
func (p *pricedList) Reheap() {
	p.heap.list = p.heap.list[:0]
	p.all.RangeRemote(func(tx *types.Transaction) bool {
		p.heap.list = append(p.heap.list, tx)
		return true
	})
	p.stales = 0
	heap.Init(&p.heap)
}

// evictStale descarta las colas de cuentas remotas inactivas. Se llama
// con el cerrojo del pool tomado. Devuelve cuántas txs se quitaron.
func (pool *TxPool) evictStale(now time.Time) int {
	if pool.config.Lifetime <= 0 {
		return 0
	}
	n := 0
	for addr, list := range pool.queue {
		if pool.locals[addr] {
			continue
		}
		if now.Sub(pool.beats[addr]) > pool.config.Lifetime {
			for _, tx := range list.Flatten() {
				pool.removeTx(tx.Hash(), true)
				n++
			}
		}
	}
	pool.metrics.Evicted.Add(uint64(n))
	return n
}
