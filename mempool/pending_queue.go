package mempool

// Este archivo implementa txList, la lista de transacciones de UNA cuenta
// indexada por nonce. El pool tiene dos por cuenta:
//
//   - pending: nonces contiguos a partir del nonce de estado (ejecutables
//     ya mismo, en orden).
//   - queue: nonces con hueco (futuros); se promueven a pending cuando el
//     hueco se llena.
//
// Además lleva cotas de coste y gas para filtrar rápidamente lo que la
// cuenta ya no puede pagar tras un cambio de estado.

import (
	"sort"

	"github.com/l1/l1/types"
)

// txList es una lista ordenada por nonce (no es segura en concurrencia; la
// protege el cerrojo del pool).
type txList struct {
	txs map[uint64]*types.Transaction
	// strict indica que los nonces deben ser contiguos (pending): al quitar
	// una, las posteriores dejan de ser válidas.
	strict bool
	// cache de nonces ordenados (se invalida al modificar).
	sorted []uint64
	// totalCost es la suma de tx.Cost() (para comprobar el saldo).
	totalCost types.Amount
}

// newTxList crea una lista vacía.
func newTxList(strict bool) *txList {
	return &txList{txs: make(map[uint64]*types.Transaction), strict: strict}
}

// keys devuelve los nonces ordenados.
func (l *txList) keys() []uint64 {
	if l.sorted == nil {
		l.sorted = make([]uint64, 0, len(l.txs))
		for n := range l.txs {
			l.sorted = append(l.sorted, n)
		}
		sort.Slice(l.sorted, func(i, j int) bool { return l.sorted[i] < l.sorted[j] })
	}
	return l.sorted
}

// put inserta sin comprobaciones.
func (l *txList) put(tx *types.Transaction) {
	if old, ok := l.txs[tx.Nonce]; ok {
		l.totalCost = l.totalCost.Sub(old.Cost())
	} else {
		l.sorted = nil
	}
	l.txs[tx.Nonce] = tx
	l.totalCost = l.totalCost.Add(tx.Cost())
}

// del borra un nonce.
func (l *txList) del(n uint64) *types.Transaction {
	tx, ok := l.txs[n]
	if !ok {
		return nil
	}
	delete(l.txs, n)
	l.sorted = nil
	l.totalCost = l.totalCost.Sub(tx.Cost())
	return tx
}

// Overlaps informa si ya hay una tx con el mismo nonce.
func (l *txList) Overlaps(tx *types.Transaction) bool { _, ok := l.txs[tx.Nonce]; return ok }

// Get devuelve la tx con ese nonce.
func (l *txList) Get(n uint64) *types.Transaction { return l.txs[n] }

// Add inserta tx; si ya hay una con el mismo nonce, sólo la reemplaza si
// supera la subida mínima de precio. Devuelve si insertó y la reemplazada.
func (l *txList) Add(tx *types.Transaction, priceBump uint64) (bool, *types.Transaction) {
	old := l.txs[tx.Nonce]
	if old != nil {
		if !CanReplace(old, tx, priceBump) {
			return false, nil
		}
	}
	l.put(tx)
	return true, old
}

// Forward quita las de nonce menor que threshold (ya incluidas en bloque).
func (l *txList) Forward(threshold uint64) []*types.Transaction {
	var removed []*types.Transaction
	for _, n := range append([]uint64(nil), l.keys()...) {
		if n >= threshold {
			break
		}
		removed = append(removed, l.del(n))
	}
	return removed
}

// Filter quita las que cuestan más que costLimit o piden más de gasLimit.
// En listas estrictas, todo lo posterior a la primera quitada se devuelve
// como inválido (deja de ser ejecutable).
func (l *txList) Filter(costLimit types.Amount, gasLimit uint64) (removed, invalids []*types.Transaction) {
	lowest := uint64(1<<64 - 1)
	for _, n := range append([]uint64(nil), l.keys()...) {
		tx := l.txs[n]
		if costLimit.Lt(tx.Cost()) || tx.Gas > gasLimit {
			removed = append(removed, l.del(n))
			if n < lowest {
				lowest = n
			}
		}
	}
	if l.strict && len(removed) > 0 {
		for _, n := range append([]uint64(nil), l.keys()...) {
			if n > lowest {
				invalids = append(invalids, l.del(n))
			}
		}
	}
	return removed, invalids
}

// Cap deja como mucho limit transacciones, quitando las de nonce mayor.
func (l *txList) Cap(limit int) []*types.Transaction {
	if len(l.txs) <= limit {
		return nil
	}
	keys := append([]uint64(nil), l.keys()...)
	var drops []*types.Transaction
	for _, n := range keys[limit:] {
		drops = append(drops, l.del(n))
	}
	return drops
}

// Remove quita una tx; en listas estrictas devuelve también las
// posteriores como inválidas.
func (l *txList) Remove(tx *types.Transaction) (bool, []*types.Transaction) {
	if cur, ok := l.txs[tx.Nonce]; !ok || cur.Hash() != tx.Hash() {
		return false, nil
	}
	l.del(tx.Nonce)
	var invalids []*types.Transaction
	if l.strict {
		for _, n := range append([]uint64(nil), l.keys()...) {
			if n > tx.Nonce {
				invalids = append(invalids, l.del(n))
			}
		}
	}
	return true, invalids
}

// Ready extrae las txs con nonces contiguos a partir de start.
func (l *txList) Ready(start uint64) []*types.Transaction {
	var ready []*types.Transaction
	for next := start; ; next++ {
		tx, ok := l.txs[next]
		if !ok {
			break
		}
		ready = append(ready, tx)
		l.del(next)
	}
	return ready
}

// Len devuelve el número de transacciones.
func (l *txList) Len() int { return len(l.txs) }

// Empty informa si está vacía.
func (l *txList) Empty() bool { return len(l.txs) == 0 }

// Flatten devuelve las transacciones en orden de nonce.
func (l *txList) Flatten() []*types.Transaction {
	out := make([]*types.Transaction, 0, len(l.txs))
	for _, n := range l.keys() {
		out = append(out, l.txs[n])
	}
	return out
}

// LastNonce devuelve el mayor nonce (y false si está vacía).
func (l *txList) LastNonce() (uint64, bool) {
	k := l.keys()
	if len(k) == 0 {
		return 0, false
	}
	return k[len(k)-1], true
}

// CostBelow suma el coste de las txs con nonce menor que n.
func (l *txList) CostBelow(n uint64) types.Amount {
	var c types.Amount
	for _, k := range l.keys() {
		if k >= n {
			break
		}
		c = c.Add(l.txs[k].Cost())
	}
	return c
}
