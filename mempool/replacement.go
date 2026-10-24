package mempool

// Este archivo define la regla de reemplazo de transacciones: una tx
// nueva con el mismo remitente y nonce que otra del pool sólo la sustituye
// si sube AMBOS precios (maxFeePerGas y maxPriorityFeePerGas) al menos un
// porcentaje (PriceBump, 10% por defecto). Así se impide inundar la red
// con reemplazos casi gratuitos y se garantiza que el reemplazo es al
// menos tan atractivo para el proponente en cualquier base fee.

import (
	"github.com/l1/l1/types"
)

// DefaultPriceBump es la subida mínima de precio para reemplazar (%).
const DefaultPriceBump = 10

// bumped devuelve a·(100+bump)/100 redondeando hacia arriba.
func bumped(a types.Amount, bump uint64) types.Amount {
	num := a.MulUint64(100 + bump)
	q := num.DivUint64(100)
	if !q.MulUint64(100).Eq(num) {
		q = q.Add(types.NewAmount(1))
	}
	return q
}

// CanReplace informa si repl puede reemplazar a old.
func CanReplace(old, repl *types.Transaction, priceBump uint64) bool {
	if old.Nonce != repl.Nonce {
		return false
	}
	if repl.GasFeeCap.Lt(bumped(old.GasFeeCap, priceBump)) {
		return false
	}
	if repl.GasTipCap.Lt(bumped(old.GasTipCap, priceBump)) {
		return false
	}
	return true
}

// MinReplacementPrices devuelve los precios mínimos que debe ofrecer un
// reemplazo de old (útil para monederos).
func MinReplacementPrices(old *types.Transaction, priceBump uint64) (feeCap, tipCap types.Amount) {
	return bumped(old.GasFeeCap, priceBump), bumped(old.GasTipCap, priceBump)
}
