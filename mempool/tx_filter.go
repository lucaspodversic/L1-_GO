package mempool

// Este archivo define filtros de admisión configurables por el operador
// del nodo: listas negras de direcciones, precio mínimo, tamaño de datos,
// sólo transferencias, etc. Se combinan con FilterChain y se aplican en la
// validación sin estado; un filtro devuelve un error para rechazar.
// También incluye utilidades para seleccionar transacciones del pool.

import (
	"errors"
	"fmt"

	"github.com/l1/l1/types"
)

// TxFilter decide si se admite una transacción.
type TxFilter interface {
	Filter(tx *types.Transaction, from types.Address) error
}

// FilterFunc adapta una función a TxFilter.
type FilterFunc func(tx *types.Transaction, from types.Address) error

// Filter implementa TxFilter.
func (f FilterFunc) Filter(tx *types.Transaction, from types.Address) error { return f(tx, from) }

// FilterChain aplica filtros en orden; el primer error rechaza.
type FilterChain []TxFilter

// Filter implementa TxFilter.
func (c FilterChain) Filter(tx *types.Transaction, from types.Address) error {
	for _, f := range c {
		if f == nil {
			continue
		}
		if err := f.Filter(tx, from); err != nil {
			return err
		}
	}
	return nil
}

// BlacklistFilter rechaza remitentes o destinatarios prohibidos.
type BlacklistFilter struct{ Addrs map[types.Address]bool }

// NewBlacklistFilter crea el filtro.
func NewBlacklistFilter(addrs ...types.Address) *BlacklistFilter {
	m := make(map[types.Address]bool, len(addrs))
	for _, a := range addrs {
		m[a] = true
	}
	return &BlacklistFilter{Addrs: m}
}

// Filter implementa TxFilter.
func (b *BlacklistFilter) Filter(tx *types.Transaction, from types.Address) error {
	if b.Addrs[from] {
		return fmt.Errorf("remitente %s en lista negra", from)
	}
	if tx.To != nil && b.Addrs[*tx.To] {
		return fmt.Errorf("destinatario %s en lista negra", *tx.To)
	}
	return nil
}

// MinFeeCapFilter exige un maxFeePerGas mínimo.
func MinFeeCapFilter(min types.Amount) TxFilter {
	return FilterFunc(func(tx *types.Transaction, _ types.Address) error {
		if tx.GasFeeCap.Lt(min) {
			return fmt.Errorf("feeCap %s < %s", tx.GasFeeCap, min)
		}
		return nil
	})
}

// MaxDataFilter limita el tamaño de los datos.
func MaxDataFilter(max int) TxFilter {
	return FilterFunc(func(tx *types.Transaction, _ types.Address) error {
		if len(tx.Data) > max {
			return fmt.Errorf("datos de %d bytes > %d", len(tx.Data), max)
		}
		return nil
	})
}

// NoContractCreationFilter rechaza despliegues.
var NoContractCreationFilter = FilterFunc(func(tx *types.Transaction, _ types.Address) error {
	if tx.To == nil {
		return errors.New("creación de contratos no admitida")
	}
	return nil
})

// SelectFunc selecciona transacciones del pool (consultas/RPC).
type SelectFunc func(tx *types.Transaction, from types.Address) bool

// BySender selecciona las de un remitente.
func BySender(a types.Address) SelectFunc {
	return func(_ *types.Transaction, from types.Address) bool { return from == a }
}

// ByRecipient selecciona las dirigidas a una dirección.
func ByRecipient(a types.Address) SelectFunc {
	return func(tx *types.Transaction, _ types.Address) bool { return tx.To != nil && *tx.To == a }
}

// MinTip selecciona las que pagan al menos esa propina con baseFee.
func MinTip(baseFee, tip types.Amount) SelectFunc {
	return func(tx *types.Transaction, _ types.Address) bool {
		t, ok := EffectiveTip(tx, baseFee)
		return ok && !t.Lt(tip)
	}
}
