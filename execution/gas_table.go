package execution

// Este archivo contiene las funciones de gas dinámico de las instrucciones
// cuyo coste depende de sus operandos o del estado (memoria, accesos
// fríos/tibios, transferencias de valor, tamaño de datos). También define
// las funciones de tamaño de memoria que indican al intérprete cuánta
// memoria necesitará cada instrucción.
//
// Convención: el coste constante de cada opcode se cobra en el intérprete;
// la función dinámica devuelve sólo el suplemento. Las funciones de gas de
// SSTORE/SLOAD viven en storage_ops.go y las de LOGn en logs_events.go.

import "github.com/l1/l1/types"

// gasFunc calcula el gas dinámico de una instrucción. memorySize ya viene
// redondeado a múltiplo de 32.
type gasFunc func(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error)

// memorySizeFunc devuelve el tamaño de memoria (en bytes, sin redondear)
// que necesita la instrucción y si su cálculo desborda.
type memorySizeFunc func(stack *Stack) (size uint64, overflow bool)

// ---------------------------------------------------------------------------
// Tamaños de memoria por instrucción
// ---------------------------------------------------------------------------

func memoryKeccak256(s *Stack) (uint64, bool)    { return calcMemSize64(s.Back(0), s.Back(1)) }
func memoryCallDataCopy(s *Stack) (uint64, bool) { return calcMemSize64(s.Back(0), s.Back(2)) }
func memoryCodeCopy(s *Stack) (uint64, bool)     { return calcMemSize64(s.Back(0), s.Back(2)) }
func memoryReturnDataCopy(s *Stack) (uint64, bool) {
	return calcMemSize64(s.Back(0), s.Back(2))
}
func memoryExtCodeCopy(s *Stack) (uint64, bool) { return calcMemSize64(s.Back(1), s.Back(3)) }
func memoryMLoad(s *Stack) (uint64, bool)       { return calcMemSize64WithUint(s.Back(0), 32) }
func memoryMStore(s *Stack) (uint64, bool)      { return calcMemSize64WithUint(s.Back(0), 32) }
func memoryMStore8(s *Stack) (uint64, bool)     { return calcMemSize64WithUint(s.Back(0), 1) }
func memoryReturn(s *Stack) (uint64, bool)      { return calcMemSize64(s.Back(0), s.Back(1)) }
func memoryRevert(s *Stack) (uint64, bool)      { return calcMemSize64(s.Back(0), s.Back(1)) }
func memoryLog(s *Stack) (uint64, bool)         { return calcMemSize64(s.Back(0), s.Back(1)) }
func memoryCreate(s *Stack) (uint64, bool)      { return calcMemSize64(s.Back(1), s.Back(2)) }
func memoryCreate2(s *Stack) (uint64, bool)     { return calcMemSize64(s.Back(1), s.Back(2)) }

// memoryMcopy: MCOPY necesita max(dst, src) + len.
func memoryMcopy(s *Stack) (uint64, bool) {
	mStart := s.Back(0) // dst
	if s.Back(1).Gt(mStart) {
		mStart = s.Back(1) // src
	}
	return calcMemSize64(mStart, s.Back(2))
}

// memoryCall: CALL/CALLCODE necesitan el mayor de los rangos de entrada
// (args) y salida (ret).
func memoryCall(s *Stack) (uint64, bool) {
	x, o1 := calcMemSize64(s.Back(5), s.Back(6))
	if o1 {
		return 0, true
	}
	y, o2 := calcMemSize64(s.Back(3), s.Back(4))
	if o2 {
		return 0, true
	}
	return max(x, y), false
}

// memoryDelegateCall: DELEGATECALL/STATICCALL no llevan valor, por lo que
// los operandos están desplazados una posición.
func memoryDelegateCall(s *Stack) (uint64, bool) {
	x, o1 := calcMemSize64(s.Back(4), s.Back(5))
	if o1 {
		return 0, true
	}
	y, o2 := calcMemSize64(s.Back(2), s.Back(3))
	if o2 {
		return 0, true
	}
	return max(x, y), false
}

// ---------------------------------------------------------------------------
// Funciones de gas dinámico
// ---------------------------------------------------------------------------

// pureMemoryGascost cobra sólo la expansión de memoria (MLOAD, MSTORE,
// RETURN, REVERT, ...).
func pureMemoryGascost(_ *EVM, _ *Contract, _ *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	return memoryGasCost(mem, memorySize)
}

// memoryCopierGas devuelve una función que cobra expansión de memoria más
// 3 gas por palabra copiada, leyendo la longitud de la posición stackpos.
func memoryCopierGas(stackpos int) gasFunc {
	return func(_ *EVM, _ *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
		gas, err := memoryGasCost(mem, memorySize)
		if err != nil {
			return 0, err
		}
		words, overflow := stack.Back(stackpos).Uint64WithOverflow()
		if overflow {
			return 0, ErrGasUintOverflow
		}
		copyGas, overflow := safeMul(toWordSize(words), CopyGas)
		if overflow {
			return 0, ErrGasUintOverflow
		}
		if gas, overflow = safeAdd(gas, copyGas); overflow {
			return 0, ErrGasUintOverflow
		}
		return gas, nil
	}
}

var (
	gasCallDataCopy   = memoryCopierGas(2)
	gasCodeCopy       = memoryCopierGas(2)
	gasReturnDataCopy = memoryCopierGas(2)
	gasMcopy          = memoryCopierGas(2)
	gasExtCodeCopyRaw = memoryCopierGas(3)
)

// gasKeccak256 cobra memoria más 6 gas por palabra hasheada.
func gasKeccak256(_ *EVM, _ *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	gas, err := memoryGasCost(mem, memorySize)
	if err != nil {
		return 0, err
	}
	size, overflow := stack.Back(1).Uint64WithOverflow()
	if overflow {
		return 0, ErrGasUintOverflow
	}
	wordGas, overflow := safeMul(toWordSize(size), Keccak256WordGas)
	if overflow {
		return 0, ErrGasUintOverflow
	}
	if gas, overflow = safeAdd(gas, wordGas); overflow {
		return 0, ErrGasUintOverflow
	}
	return gas, nil
}

// gasExp cobra 50 gas por cada byte significativo del exponente.
func gasExp(_ *EVM, _ *Contract, stack *Stack, _ *Memory, _ uint64) (uint64, error) {
	expBytes := uint64(stack.Back(1).ByteLen())
	return expBytes * ExpByteGas, nil // como mucho 32*50, no desborda
}

// accessAccount marca addr como tibia y devuelve el suplemento por acceso
// frío (2600 - 100, porque los 100 tibios ya forman parte del coste fijo).
func accessAccount(evm *EVM, addr types.Address) uint64 {
	if evm.StateDB.AddressInAccessList(addr) {
		return 0
	}
	evm.StateDB.AddAddressToAccessList(addr)
	return ColdAccountAccessCost - WarmStorageReadCost
}

// gasAccountAccess sirve a BALANCE, EXTCODESIZE y EXTCODEHASH (EIP-2929).
func gasAccountAccess(evm *EVM, _ *Contract, stack *Stack, _ *Memory, _ uint64) (uint64, error) {
	return accessAccount(evm, stack.Back(0).Address()), nil
}

// gasExtCodeCopy suma al copiado de memoria el acceso frío a la cuenta.
func gasExtCodeCopy(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	gas, err := gasExtCodeCopyRaw(evm, contract, stack, mem, memorySize)
	if err != nil {
		return 0, err
	}
	cold := accessAccount(evm, stack.Back(0).Address())
	if gas, overflow := safeAdd(gas, cold); !overflow {
		return gas, nil
	}
	return 0, ErrGasUintOverflow
}

// callKind distingue las variantes de CALL para el cálculo de gas.
type callKind int

const (
	kindCall callKind = iota
	kindCallCode
	kindDelegateCall
	kindStaticCall
)

// makeCallGas construye la función de gas de una variante de CALL:
//
//  1. acceso frío al destino (EIP-2929);
//  2. transferencia de valor (9000) y, sólo en CALL, creación de cuenta
//     nueva (25000) si el destino está vacío (EIP-161);
//  3. expansión de memoria;
//  4. gas reenviado a la sub-llamada según la regla 63/64, que se guarda en
//     evm.callGasTemp para que la instrucción lo use.
func makeCallGas(kind callKind) gasFunc {
	return func(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
		addr := stack.Back(1).Address()
		gas := accessAccount(evm, addr)
		if kind == kindCall || kind == kindCallCode {
			if !stack.Back(2).IsZero() {
				gas += CallValueGas
				if kind == kindCall && evm.StateDB.Empty(addr) {
					gas += CallNewAccGas
				}
			}
		}
		memGas, err := memoryGasCost(mem, memorySize)
		if err != nil {
			return 0, err
		}
		var overflow bool
		if gas, overflow = safeAdd(gas, memGas); overflow {
			return 0, ErrGasUintOverflow
		}
		evm.callGasTemp, err = callGas(contract.Gas, gas, stack.Back(0))
		if err != nil {
			return 0, err
		}
		if gas, overflow = safeAdd(gas, evm.callGasTemp); overflow {
			return 0, ErrGasUintOverflow
		}
		return gas, nil
	}
}

var (
	gasCall         = makeCallGas(kindCall)
	gasCallCode     = makeCallGas(kindCallCode)
	gasDelegateCall = makeCallGas(kindDelegateCall)
	gasStaticCall   = makeCallGas(kindStaticCall)
)

// gasCreate cobra memoria y 2 gas por palabra de initcode (EIP-3860).
func gasCreate(_ *EVM, _ *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	return createGasCommon(stack, mem, memorySize, InitCodeWordGas)
}

// gasCreate2 además cobra el hash del initcode (6 gas por palabra).
func gasCreate2(_ *EVM, _ *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	return createGasCommon(stack, mem, memorySize, InitCodeWordGas+Keccak256WordGas)
}

// createGasCommon rechaza initcode por encima de MaxInitCodeSize y cobra
// perWord por cada palabra.
func createGasCommon(stack *Stack, mem *Memory, memorySize, perWord uint64) (uint64, error) {
	gas, err := memoryGasCost(mem, memorySize)
	if err != nil {
		return 0, err
	}
	size, overflow := stack.Back(2).Uint64WithOverflow()
	if overflow || size > maxInitCodeSize {
		return 0, ErrGasUintOverflow
	}
	more := toWordSize(size) * perWord // acotado: size <= 49152
	if gas, overflow = safeAdd(gas, more); overflow {
		return 0, ErrGasUintOverflow
	}
	return gas, nil
}

// gasSelfdestruct: acceso frío al beneficiario (2600 completos, porque el
// coste fijo de 5000 no incluye lectura tibia) y 25000 si se envía saldo a
// una cuenta vacía. Desde EIP-3529 no hay reembolso.
func gasSelfdestruct(evm *EVM, contract *Contract, stack *Stack, _ *Memory, _ uint64) (uint64, error) {
	var gas uint64
	addr := stack.Back(0).Address()
	if !evm.StateDB.AddressInAccessList(addr) {
		evm.StateDB.AddAddressToAccessList(addr)
		gas = ColdAccountAccessCost
	}
	if evm.StateDB.Empty(addr) && !evm.StateDB.GetBalance(contract.Address()).IsZero() {
		gas += CreateBySDGas
	}
	return gas, nil
}
