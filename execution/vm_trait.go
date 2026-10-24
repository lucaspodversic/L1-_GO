// Package execution implementa la capa de ejecución de la cadena: una
// máquina virtual compatible con la EVM (opcodes, gas, precompilados), el
// procesamiento de transacciones y bloques con el mercado de comisiones
// EIP-1559, contratos de sistema nativos y utilidades de trazado.
//
// Organización del paquete:
//
//   - vm_trait.go, opcodes.go, stack.go, memory.go, call_frame.go: piezas
//     básicas del intérprete (interfaces, códigos de operación, pila de
//     palabras de 256 bits, memoria lineal y marco de llamada).
//   - gas.go, gas_table.go: constantes y funciones de gas dinámico.
//   - interpreter.go: el bucle principal y la tabla de saltos.
//   - executor.go, contract_call.go, contract_create.go: el objeto EVM y las
//     operaciones CALL*/CREATE*.
//   - precompiles*.go: contratos precompilados (ecrecover, sha256, ...).
//   - state_transition.go, tx_processor.go, block_processor.go: aplicación
//     de transacciones y bloques sobre el estado.
//   - fee_market.go, base_fee.go, intrinsic_gas.go, access_list.go: reglas
//     económicas (EIP-1559, EIP-2930).
//   - system_contracts.go, native_transfer.go, abi.go, tracing.go,
//     executor_service.go: integración con el resto del nodo.
//
// La EVM implementa un único conjunto de reglas fijo, equivalente a Cancún
// sin blobs (EIP-4844): como la cadena es nueva no necesitamos reproducir
// el historial de bifurcaciones de Ethereum.
package execution

// Este archivo declara las interfaces que la VM necesita del exterior. La
// implementación concreta del estado es storage.StateDB, pero la VM depende
// sólo de la interfaz StateDB, lo que permite probarla con estados
// simulados y evita acoplar el intérprete a la capa de almacenamiento.

import (
	"github.com/l1/l1/storage"
	"github.com/l1/l1/types"
)

// StateDB es la vista mutable del estado mundial que usa la EVM. Todas las
// modificaciones deben ser revertibles mediante Snapshot/RevertToSnapshot,
// porque cada sub-llamada puede fallar y deshacer sus efectos.
type StateDB interface {
	// --- Cuentas ---

	// CreateAccount crea (o reinicia) una cuenta conservando su saldo.
	CreateAccount(types.Address)
	// CreateContract marca la cuenta como contrato creado en esta
	// transacción (relevante para SELFDESTRUCT según EIP-6780).
	CreateContract(types.Address)
	// Exist informa si la cuenta existe en el estado.
	Exist(types.Address) bool
	// Empty informa si la cuenta está vacía según EIP-161
	// (nonce 0, saldo 0 y sin código).
	Empty(types.Address) bool

	// --- Saldo y nonce ---

	GetBalance(types.Address) types.Amount
	AddBalance(types.Address, types.Amount)
	// SubBalance devuelve error si el saldo es insuficiente.
	SubBalance(types.Address, types.Amount) error
	GetNonce(types.Address) uint64
	SetNonce(types.Address, uint64)

	// --- Código ---

	GetCode(types.Address) []byte
	GetCodeSize(types.Address) int
	// GetCodeHash devuelve el hash cero si la cuenta no existe.
	GetCodeHash(types.Address) types.Hash
	SetCode(types.Address, []byte)

	// --- Almacenamiento persistente y transitorio ---

	GetState(types.Address, types.Hash) types.Hash
	// GetCommittedState devuelve el valor al inicio de la transacción
	// (necesario para el cálculo de gas de SSTORE, EIP-2200).
	GetCommittedState(types.Address, types.Hash) types.Hash
	SetState(types.Address, types.Hash, types.Hash)
	GetStorageRoot(types.Address) types.Hash
	GetTransientState(types.Address, types.Hash) types.Hash
	SetTransientState(types.Address, types.Hash, types.Hash)

	// --- Autodestrucción ---

	SelfDestruct(types.Address)
	HasSelfDestructed(types.Address) bool
	// SelfDestruct6780 destruye sólo si el contrato se creó en esta misma
	// transacción; devuelve true si lo hizo.
	SelfDestruct6780(types.Address) bool

	// --- Reembolsos ---

	AddRefund(uint64)
	SubRefund(uint64)
	GetRefund() uint64

	// --- Listas de acceso (EIP-2929/2930) ---

	AddressInAccessList(types.Address) bool
	SlotInAccessList(types.Address, types.Hash) (addressOk bool, slotOk bool)
	AddAddressToAccessList(types.Address)
	AddSlotToAccessList(types.Address, types.Hash)
	Prepare(sender, coinbase types.Address, dst *types.Address, precompiles []types.Address, list types.AccessList)

	// --- Instantáneas y registros ---

	Snapshot() int
	RevertToSnapshot(int)
	AddLog(*types.Log)
}

// Comprobación en tiempo de compilación: storage.StateDB satisface la
// interfaz que necesita la VM.
var _ StateDB = (*storage.StateDB)(nil)

// ChainContext da acceso a cabeceras anteriores (para BLOCKHASH).
type ChainContext interface {
	// GetHeader devuelve la cabecera con el hash y número indicados, o nil.
	GetHeader(hash types.Hash, number uint64) *types.Header
}

// HeaderByNumberReader es una alternativa más simple que permite resolver
// BLOCKHASH a partir del número del bloque.
type HeaderByNumberReader interface {
	HeaderByNumber(number uint64) (*types.Header, error)
}

// VM es la interfaz pública de la máquina virtual. Las cuatro variantes de
// llamada difieren en el contexto que conservan:
//
//   - Call: nuevo contexto en el destino, con transferencia de valor.
//   - CallCode: ejecuta el código del destino en el contexto del llamante.
//   - DelegateCall: como CallCode pero conserva caller y value originales.
//   - StaticCall: prohíbe cualquier modificación de estado.
type VM interface {
	Call(caller, addr types.Address, input []byte, gas uint64, value *Word) (ret []byte, leftOverGas uint64, err error)
	CallCode(caller, addr types.Address, input []byte, gas uint64, value *Word) (ret []byte, leftOverGas uint64, err error)
	DelegateCall(originCaller, caller, addr types.Address, input []byte, gas uint64, value *Word) (ret []byte, leftOverGas uint64, err error)
	StaticCall(caller, addr types.Address, input []byte, gas uint64) (ret []byte, leftOverGas uint64, err error)
	Create(caller types.Address, code []byte, gas uint64, value *Word) (ret []byte, contractAddr types.Address, leftOverGas uint64, err error)
	Create2(caller types.Address, code []byte, gas uint64, value *Word, salt *Word) (ret []byte, contractAddr types.Address, leftOverGas uint64, err error)
}

// Comprobación: *EVM implementa VM.
var _ VM = (*EVM)(nil)
