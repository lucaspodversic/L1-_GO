package execution

// Este archivo calcula el gas intrínseco: lo que una transacción paga
// antes de ejecutar una sola instrucción. Cubre el coste fijo (21000, o
// 53000 si crea un contrato), los bytes de datos (4 por byte cero, 16 por
// byte no cero), la lista de acceso EIP-2930 (2400 por dirección y 1900 por
// ranura) y las palabras de initcode (EIP-3860, 2 por palabra).
//
// types.Transaction.IntrinsicGas hace el mismo cálculo sobre una tx; aquí
// se expone en forma de función libre para mensajes sin firmar
// (eth_call/eth_estimateGas) y con comprobación de desbordamiento.

import (
	"math"

	"github.com/l1/l1/types"
)

// IntrinsicGas calcula el gas intrínseco de datos, lista de acceso y tipo.
func IntrinsicGas(data []byte, accessList types.AccessList, isContractCreation bool) (uint64, error) {
	gas := types.TxGas
	if isContractCreation {
		gas = types.TxGasContractCreation
	}
	dataLen := uint64(len(data))
	if dataLen > 0 {
		var nz uint64
		for _, b := range data {
			if b != 0 {
				nz++
			}
		}
		// Comprobaciones de desbordamiento al estilo de geth.
		if (math.MaxUint64-gas)/types.TxDataNonZeroGas < nz {
			return 0, ErrGasUintOverflow
		}
		gas += nz * types.TxDataNonZeroGas
		z := dataLen - nz
		if (math.MaxUint64-gas)/types.TxDataZeroGas < z {
			return 0, ErrGasUintOverflow
		}
		gas += z * types.TxDataZeroGas
		if isContractCreation {
			words := toWordSize(dataLen)
			if (math.MaxUint64-gas)/types.InitCodeWordGas < words {
				return 0, ErrGasUintOverflow
			}
			gas += words * types.InitCodeWordGas
		}
	}
	if accessList != nil {
		addrGas, overflow := safeMul(uint64(len(accessList)), types.TxAccessListAddressGas)
		if overflow {
			return 0, ErrGasUintOverflow
		}
		keyGas, overflow := safeMul(uint64(accessList.StorageKeys()), types.TxAccessListStorageKeyGas)
		if overflow {
			return 0, ErrGasUintOverflow
		}
		var o1, o2 bool
		gas, o1 = safeAdd(gas, addrGas)
		gas, o2 = safeAdd(gas, keyGas)
		if o1 || o2 {
			return 0, ErrGasUintOverflow
		}
	}
	return gas, nil
}

// TxIntrinsicGas es un atajo para una transacción.
func TxIntrinsicGas(tx *types.Transaction) (uint64, error) {
	return IntrinsicGas(tx.Data, tx.AccessList, tx.To == nil)
}

// DataGas devuelve sólo el coste de los bytes de datos (sin el fijo), útil
// para estimar el coste de calldata en herramientas.
func DataGas(data []byte) uint64 {
	var g uint64
	for _, b := range data {
		if b == 0 {
			g += types.TxDataZeroGas
		} else {
			g += types.TxDataNonZeroGas
		}
	}
	return g
}
