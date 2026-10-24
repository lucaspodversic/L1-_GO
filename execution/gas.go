package execution

// Este archivo reúne las constantes de gas de la EVM (valores de Cancún) y
// las utilidades aritméticas para calcularlo sin desbordamientos: coste de
// expansión de memoria, regla 63/64 de las llamadas (EIP-150) y conversión
// a palabras.

import (
	"math"
	"math/bits"
)

// Niveles de coste constante de las instrucciones simples.
const (
	GasQuickStep   uint64 = 2
	GasFastestStep uint64 = 3
	GasFastStep    uint64 = 5
	GasMidStep     uint64 = 8
	GasSlowStep    uint64 = 10
	GasExtStep     uint64 = 20
)

// Costes específicos de instrucciones.
const (
	Keccak256Gas     uint64 = 30 // base de KECCAK256
	Keccak256WordGas uint64 = 6  // por palabra hasheada
	CopyGas          uint64 = 3  // por palabra copiada (CALLDATACOPY, ...)
	MemoryGas        uint64 = 3  // término lineal de la expansión de memoria
	QuadCoeffDiv     uint64 = 512
	ExpGas           uint64 = 10 // base de EXP
	ExpByteGas       uint64 = 50 // por byte del exponente (EIP-160)
	LogGas           uint64 = 375
	LogTopicGas      uint64 = 375
	LogDataGas       uint64 = 8
	JumpdestGas      uint64 = 1
	BlockhashGas     uint64 = 20

	CreateGas        uint64 = 32000
	CreateDataGas    uint64 = 200 // por byte de código desplegado
	InitCodeWordGas  uint64 = 2   // EIP-3860, por palabra de initcode
	CallStipend      uint64 = 2300
	CallValueGas     uint64 = 9000
	CallNewAccGas    uint64 = 25000
	SelfdestructGas  uint64 = 5000
	CreateBySDGas    uint64 = 25000 // SELFDESTRUCT a cuenta vacía con saldo
	CallCreateDepth  uint64 = 1024
	MaxRefundDivisor uint64 = 5 // EIP-3529: reembolso <= gasUsado/5

	// EIP-2929: accesos fríos/tibios.
	ColdAccountAccessCost uint64 = 2600
	ColdSloadCost         uint64 = 2100
	WarmStorageReadCost   uint64 = 100

	// EIP-2200 + EIP-2929 + EIP-3529: SSTORE.
	SstoreSentryGas uint64 = 2300  // gas mínimo restante para permitir SSTORE
	SstoreSetGas    uint64 = 20000 // 0 -> no cero
	SstoreResetGas  uint64 = 5000  // no cero -> otro valor (antes de 2929)
	// SstoreClearsScheduleRefund = SSTORE_RESET - COLD_SLOAD + ACCESS_LIST_STORAGE_KEY.
	SstoreClearsScheduleRefund uint64 = 4800

	// EIP-1153: almacenamiento transitorio.
	TloadGas  uint64 = 100
	TstoreGas uint64 = 100
)

// maxMemorySize es el mayor tamaño de memoria cuyo coste de gas no desborda
// uint64 (0x1FFFFFFFE0, el mismo límite que usa geth).
const maxMemorySize = 0x1FFFFFFFE0

// toWordSize redondea un tamaño en bytes a palabras de 32 bytes.
func toWordSize(size uint64) uint64 {
	if size > math.MaxUint64-31 {
		return math.MaxUint64/32 + 1
	}
	return (size + 31) / 32
}

// safeAdd suma informando del desbordamiento.
func safeAdd(a, b uint64) (uint64, bool) {
	s, c := bits.Add64(a, b, 0)
	return s, c != 0
}

// safeMul multiplica informando del desbordamiento.
func safeMul(a, b uint64) (uint64, bool) {
	hi, lo := bits.Mul64(a, b)
	return lo, hi != 0
}

// memoryGasCost devuelve el gas ADICIONAL para expandir la memoria hasta
// newSize bytes. La fórmula total es 3·w + w²/512 (w = palabras); se cobra la
// diferencia respecto a lo ya pagado. newSize debe ser múltiplo de 32.
func memoryGasCost(mem *Memory, newSize uint64) (uint64, error) {
	if newSize == 0 {
		return 0, nil
	}
	if newSize > maxMemorySize {
		return 0, ErrGasUintOverflow
	}
	if newSize <= uint64(mem.Len()) {
		return 0, nil
	}
	words := toWordSize(newSize)
	total := words*MemoryGas + words*words/QuadCoeffDiv
	if total > mem.lastGasCost {
		fee := total - mem.lastGasCost
		mem.lastGasCost = total
		return fee, nil
	}
	return 0, nil
}

// callGas aplica la regla 63/64 (EIP-150): una sub-llamada puede recibir
// como máximo todo el gas disponible menos 1/64. Si el gas solicitado en la
// pila es menor, se usa ese.
func callGas(availableGas, base uint64, requested *Word) (uint64, error) {
	if availableGas < base {
		return 0, ErrOutOfGas
	}
	availableGas -= base
	maxGas := availableGas - availableGas/64
	if !requested.IsUint64() || requested.Uint64() > maxGas {
		return maxGas, nil
	}
	return requested.Uint64(), nil
}

// calcMemSize64 devuelve offset+length como uint64 (tamaño de memoria que
// necesita una operación). Si length es cero no se necesita memoria aunque
// el offset sea enorme. Informa de desbordamiento.
func calcMemSize64(off, l *Word) (uint64, bool) {
	if !l.IsUint64() {
		return 0, true
	}
	return calcMemSize64WithUint(off, l.Uint64())
}

// calcMemSize64WithUint es como calcMemSize64 con longitud constante.
func calcMemSize64WithUint(off *Word, length uint64) (uint64, bool) {
	if length == 0 {
		return 0, false
	}
	if !off.IsUint64() {
		return 0, true
	}
	return safeAdd(off.Uint64(), length)
}
