package mempool

// Este archivo ordena las transacciones ejecutables para construir un
// bloque. Entre cuentas se elige la de mayor propina efectiva para la base
// fee del bloque (min(tipCap, feeCap − baseFee)); dentro de cada cuenta se
// respeta el orden de nonce. Se usa un montículo con la cabeza de cada
// cuenta, como TransactionsByPriceAndNonce de geth. Implementa
// execution.TxIterator.

import (
	"container/heap"
	"time"

	"github.com/l1/l1/execution"
	"github.com/l1/l1/types"
)

// EffectiveTip devuelve la propina efectiva y false si feeCap < baseFee.
func EffectiveTip(tx *types.Transaction, baseFee types.Amount) (types.Amount, bool) {
	if tx.GasFeeCap.Lt(baseFee) {
		return types.Amount{}, false
	}
	return tx.GasTipCap.Min(tx.GasFeeCap.Sub(baseFee)), true
}

// txWithTip es la cabeza de una cuenta en el montículo.
type txWithTip struct {
	tx   *types.Transaction
	from types.Address
	tip  types.Amount
	seen time.Time // desempate: la más antigua primero
}

// tipHeap es un max-heap por propina.
type tipHeap []*txWithTip

func (h tipHeap) Len() int { return len(h) }
func (h tipHeap) Less(i, j int) bool {
	if c := h[i].tip.Cmp(h[j].tip); c != 0 {
		return c > 0
	}
	if !h[i].seen.Equal(h[j].seen) {
		return h[i].seen.Before(h[j].seen)
	}
	return string(h[i].from[:]) < string(h[j].from[:]) // determinista
}
func (h tipHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *tipHeap) Push(x any)   { *h = append(*h, x.(*txWithTip)) }
func (h *tipHeap) Pop() any {
	old := *h
	x := old[len(old)-1]
	*h = old[:len(old)-1]
	return x
}

// TransactionsByPriceAndNonce es el iterador ordenado.
type TransactionsByPriceAndNonce struct {
	txs     map[types.Address][]*types.Transaction
	heads   tipHeap
	baseFee types.Amount
	seen    func(types.Hash) time.Time
}

var _ execution.TxIterator = (*TransactionsByPriceAndNonce)(nil)

// NewTransactionsByPriceAndNonce crea el iterador. txs debe tener por
// cuenta una lista ordenada por nonce y contigua. seen (opcional) da la
// hora de llegada de cada tx para desempatar.
func NewTransactionsByPriceAndNonce(txs map[types.Address][]*types.Transaction, baseFee types.Amount, seen func(types.Hash) time.Time) *TransactionsByPriceAndNonce {
	it := &TransactionsByPriceAndNonce{txs: make(map[types.Address][]*types.Transaction, len(txs)), baseFee: baseFee, seen: seen}
	for from, list := range txs {
		if len(list) == 0 {
			continue
		}
		it.txs[from] = list
		if w := it.wrap(from, list[0]); w != nil {
			it.heads = append(it.heads, w)
		}
	}
	heap.Init(&it.heads)
	return it
}

// wrap calcula la propina de la cabeza (nil si no es incluible).
func (it *TransactionsByPriceAndNonce) wrap(from types.Address, tx *types.Transaction) *txWithTip {
	tip, ok := EffectiveTip(tx, it.baseFee)
	if !ok {
		return nil
	}
	w := &txWithTip{tx: tx, from: from, tip: tip}
	if it.seen != nil {
		w.seen = it.seen(tx.Hash())
	}
	return w
}

// Peek devuelve la mejor transacción actual.
func (it *TransactionsByPriceAndNonce) Peek() *types.Transaction {
	if len(it.heads) == 0 {
		return nil
	}
	return it.heads[0].tx
}

// Shift avanza a la siguiente transacción de la misma cuenta.
func (it *TransactionsByPriceAndNonce) Shift() {
	if len(it.heads) == 0 {
		return
	}
	from := it.heads[0].from
	if rest := it.txs[from][1:]; len(rest) > 0 {
		it.txs[from] = rest
		if w := it.wrap(from, rest[0]); w != nil {
			it.heads[0] = w
			heap.Fix(&it.heads, 0)
			return
		}
	}
	delete(it.txs, from)
	heap.Pop(&it.heads)
}

// Pop descarta la cuenta actual entera.
func (it *TransactionsByPriceAndNonce) Pop() {
	if len(it.heads) == 0 {
		return
	}
	delete(it.txs, it.heads[0].from)
	heap.Pop(&it.heads)
}

// Empty informa si no quedan transacciones.
func (it *TransactionsByPriceAndNonce) Empty() bool { return len(it.heads) == 0 }
