package execution

// Este archivo implementa el trazador de lista de acceso (base de
// eth_createAccessList): observa las instrucciones que leen cuentas o
// ranuras (SLOAD, SSTORE, BALANCE, EXTCODE*, CALL*, SELFDESTRUCT) y
// construye la lista EIP-2930 que habría que declarar para que esos
// accesos fueran "tibios" desde el principio.
//
// Se excluyen las direcciones que ya son tibias sin declararlas (emisor,
// destinatario, precompilados, contratos de sistema y coinbase), porque
// declararlas sólo costaría 2400 de gas extra.

import (
	"sort"

	"github.com/l1/l1/types"
)

// accessSet es un conjunto dirección -> ranuras.
type accessSet map[types.Address]map[types.Hash]struct{}

func (s accessSet) addAddress(a types.Address) {
	if _, ok := s[a]; !ok {
		s[a] = make(map[types.Hash]struct{})
	}
}

func (s accessSet) addSlot(a types.Address, k types.Hash) {
	s.addAddress(a)
	s[a][k] = struct{}{}
}

// AccessListTracer acumula los accesos de una ejecución.
type AccessListTracer struct {
	list     accessSet
	excluded map[types.Address]struct{}
}

// NewAccessListTracer crea el trazador partiendo de una lista previa (los
// accesos ya declarados se conservan) y excluyendo las direcciones dadas.
func NewAccessListTracer(initial types.AccessList, excluded []types.Address) *AccessListTracer {
	t := &AccessListTracer{list: make(accessSet), excluded: make(map[types.Address]struct{})}
	for _, a := range excluded {
		t.excluded[a] = struct{}{}
	}
	for _, tup := range initial {
		if _, ex := t.excluded[tup.Address]; ex {
			continue
		}
		t.list.addAddress(tup.Address)
		for _, k := range tup.StorageKeys {
			t.list.addSlot(tup.Address, k)
		}
	}
	return t
}

func (t *AccessListTracer) touchAddr(a types.Address) {
	if _, ex := t.excluded[a]; !ex {
		t.list.addAddress(a)
	}
}

// Hooks devuelve el gancho OnOpcode que alimenta la lista.
func (t *AccessListTracer) Hooks() *Hooks {
	return &Hooks{
		OnOpcode: func(_ uint64, op OpCode, _, _ uint64, scope *ScopeContext, _ []byte, _ int, _ error) {
			data := scope.StackData()
			n := len(data)
			back := func(i int) *Word { return &data[n-1-i] }
			switch {
			case (op == SLOAD || op == SSTORE) && n >= 1:
				// Las ranuras se registran aunque la dirección esté excluida
				// (p.ej. el destinatario): declarar la ranura sí ahorra gas.
				t.list.addSlot(scope.Address(), back(0).Hash())
			case (op == EXTCODECOPY || op == EXTCODEHASH || op == EXTCODESIZE || op == BALANCE || op == SELFDESTRUCT) && n >= 1:
				t.touchAddr(back(0).Address())
			case (op == DELEGATECALL || op == CALL || op == STATICCALL || op == CALLCODE) && n >= 5:
				t.touchAddr(back(1).Address())
			}
		},
	}
}

// AccessList devuelve la lista acumulada en orden determinista.
func (t *AccessListTracer) AccessList() types.AccessList {
	addrs := make([]types.Address, 0, len(t.list))
	for a := range t.list {
		addrs = append(addrs, a)
	}
	sort.Slice(addrs, func(i, j int) bool { return string(addrs[i][:]) < string(addrs[j][:]) })
	out := make(types.AccessList, 0, len(addrs))
	for _, a := range addrs {
		keys := make([]types.Hash, 0, len(t.list[a]))
		for k := range t.list[a] {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return string(keys[i][:]) < string(keys[j][:]) })
		out = append(out, types.AccessTuple{Address: a, StorageKeys: keys})
	}
	return out
}

// Equal informa si la lista coincide con otra (para iterar hasta un punto
// fijo: una lista nueva puede cambiar el camino de ejecución).
func (t *AccessListTracer) Equal(other *AccessListTracer) bool {
	if len(t.list) != len(other.list) {
		return false
	}
	for a, slots := range t.list {
		os, ok := other.list[a]
		if !ok || len(os) != len(slots) {
			return false
		}
		for k := range slots {
			if _, ok := os[k]; !ok {
				return false
			}
		}
	}
	return true
}

// AccessListGas devuelve el gas intrínseco que añade declarar la lista.
func AccessListGas(al types.AccessList) uint64 {
	return uint64(len(al))*types.TxAccessListAddressGas + uint64(al.StorageKeys())*types.TxAccessListStorageKeyGas
}
