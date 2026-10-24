package execution

// Este archivo define EVM, el objeto que coordina una ejecución: guarda el
// contexto de bloque y transacción, el estado, la configuración, el
// intérprete y la profundidad de llamadas. Las operaciones de llamada y
// creación (que son métodos de EVM) viven en contract_call.go y
// contract_create.go. Una EVM no es segura para uso concurrente; se crea
// una por transacción (o se reutiliza con SetTxContext dentro del bloque).

import (
	"sync/atomic"

	"github.com/l1/l1/types"
)

// EVM es la máquina virtual de la cadena.
type EVM struct {
	// Context es el contexto del bloque (constante en el bloque).
	Context BlockContext
	// TxContext es el contexto de la transacción en curso.
	TxContext TxContext
	// StateDB es el estado sobre el que se ejecuta.
	StateDB StateDB
	// ChainConfig es la configuración de la cadena.
	ChainConfig *ChainConfig
	// Config son las opciones de la VM (trazador, etc.).
	Config Config

	interpreter *Interpreter
	precompiles map[types.Address]PrecompiledContract
	system      map[types.Address]SystemContract

	// depth es la profundidad de llamada actual (0 = transacción).
	depth int
	// abort permite cancelar la ejecución desde otra goroutine.
	abort atomic.Bool
	// callGasTemp transporta el gas calculado por la función de gas de
	// CALL* hasta la instrucción (evita recalcular la regla 63/64).
	callGasTemp uint64
}

// NewEVM crea una EVM lista para ejecutar.
func NewEVM(blockCtx BlockContext, txCtx TxContext, statedb StateDB, chainConfig *ChainConfig, config Config) *EVM {
	if chainConfig == nil {
		chainConfig = DefaultChainConfig(types.DevnetChainID)
	}
	if blockCtx.CanTransfer == nil {
		blockCtx.CanTransfer = CanTransfer
	}
	if blockCtx.Transfer == nil {
		blockCtx.Transfer = Transfer
	}
	if blockCtx.GetHash == nil {
		blockCtx.GetHash = func(uint64) types.Hash { return types.Hash{} }
	}
	evm := &EVM{
		Context:     blockCtx,
		TxContext:   txCtx,
		StateDB:     statedb,
		ChainConfig: chainConfig,
		Config:      config,
		precompiles: activePrecompiles,
		system:      DefaultSystemContracts(),
	}
	for a, c := range chainConfig.SystemContracts {
		evm.system[a] = c
	}
	evm.interpreter = NewInterpreter(evm)
	return evm
}

// SetTxContext cambia el contexto de transacción (reutilización por bloque).
func (evm *EVM) SetTxContext(txCtx TxContext) { evm.TxContext = txCtx }

// Interpreter devuelve el intérprete asociado.
func (evm *EVM) Interpreter() *Interpreter { return evm.interpreter }

// Depth devuelve la profundidad de llamada actual.
func (evm *EVM) Depth() int { return evm.depth }

// Cancel aborta la ejecución en curso en cuanto sea posible (es seguro
// llamarlo desde otra goroutine).
func (evm *EVM) Cancel() { evm.abort.Store(true) }

// Cancelled informa si se pidió abortar.
func (evm *EVM) Cancelled() bool { return evm.abort.Load() }

// precompile devuelve el precompilado en addr, si existe.
func (evm *EVM) precompile(addr types.Address) (PrecompiledContract, bool) {
	p, ok := evm.precompiles[addr]
	return p, ok
}

// systemContract devuelve el contrato de sistema nativo en addr, si existe.
func (evm *EVM) systemContract(addr types.Address) (SystemContract, bool) {
	if evm.system == nil {
		return nil, false
	}
	c, ok := evm.system[addr]
	return c, ok
}

// SetSystemContracts sustituye el conjunto de contratos de sistema (útil en
// pruebas o para desactivarlos con nil).
func (evm *EVM) SetSystemContracts(m map[types.Address]SystemContract) { evm.system = m }

// ActivePrecompileAddresses devuelve las direcciones de precompilados y
// contratos de sistema, que se precalientan en la lista de acceso de cada
// transacción (EIP-2929).
func (evm *EVM) ActivePrecompileAddresses() []types.Address {
	out := append([]types.Address(nil), precompileAddresses...)
	for a := range evm.system {
		out = append(out, a)
	}
	return out
}

// tracerEnter notifica el inicio de un marco al trazador.
func (evm *EVM) tracerEnter(typ OpCode, from, to types.Address, input []byte, gas uint64, value *Word) {
	if h := evm.Config.Tracer; h != nil && h.OnEnter != nil {
		h.OnEnter(evm.depth, typ, from, to, input, gas, value)
	}
}

// tracerExit notifica el fin de un marco al trazador.
func (evm *EVM) tracerExit(output []byte, startGas, leftGas uint64, err error) {
	if h := evm.Config.Tracer; h != nil && h.OnExit != nil {
		h.OnExit(evm.depth, output, startGas-leftGas, err, err != nil && err == ErrExecutionReverted)
	}
}
