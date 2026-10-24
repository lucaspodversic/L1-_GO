package execution

// Este archivo contiene el intérprete de bytecode: la tabla de saltos que
// asocia cada opcode con su implementación, coste y requisitos de pila, el
// bucle principal de ejecución y las instrucciones "puras" (aritmética,
// bits, pila, memoria y control de flujo). Las instrucciones que tocan el
// entorno, el almacenamiento, los registros, las llamadas y la creación de
// contratos están en sus propios archivos.

import (
	"errors"

	"github.com/l1/l1/types"
)

// Config ajusta el comportamiento de la EVM.
type Config struct {
	// Tracer recibe eventos de ejecución (puede ser nil).
	Tracer *Hooks
	// NoBaseFee permite precios de gas por debajo de la base fee (útil
	// para eth_call y estimaciones, donde no se paga gas real).
	NoBaseFee bool
}

// executionFunc implementa una instrucción. Devuelve datos sólo las que
// terminan el marco con salida (RETURN, REVERT).
type executionFunc func(pc *uint64, in *Interpreter, scope *ScopeContext) ([]byte, error)

// operation describe una instrucción en la tabla de saltos.
type operation struct {
	execute     executionFunc
	constantGas uint64
	dynamicGas  gasFunc
	// minStack es el mínimo de elementos que debe haber en la pila y
	// maxStack el máximo admisible antes de ejecutarla (para no superar
	// StackLimit tras los push).
	minStack, maxStack int
	memorySize         memorySizeFunc
	undefined          bool
}

// JumpTable asocia cada uno de los 256 opcodes con su operación.
type JumpTable [256]*operation

// minStack/maxStack calculan los límites a partir de pops y pushes.
func minStack(pops, _ int) int      { return pops }
func maxStack(pops, pushes int) int { return StackLimit + pops - pushes }

// errStopToken es un centinela interno: la instrucción terminó el marco con
// éxito (STOP, RETURN, SELFDESTRUCT).
var errStopToken = errors.New("stop token")

// Interpreter ejecuta bytecode en el contexto de una EVM.
type Interpreter struct {
	evm   *EVM
	table *JumpTable

	// readOnly indica un contexto STATICCALL: cualquier escritura falla.
	readOnly bool
	// returnData son los datos devueltos por la última sub-llamada
	// (RETURNDATASIZE/RETURNDATACOPY).
	returnData []byte
}

// NewInterpreter crea un intérprete con la tabla de saltos de la cadena.
func NewInterpreter(evm *EVM) *Interpreter {
	return &Interpreter{evm: evm, table: &defaultJumpTable}
}

// Run ejecuta el código del contrato con la entrada dada. Con readOnly
// activa el modo estático durante esta llamada y sus descendientes.
// Devuelve los datos de salida y un error; ErrExecutionReverted conserva
// los datos de salida (motivo del revert) y no consume todo el gas.
func (in *Interpreter) Run(contract *Contract, input []byte, readOnly bool) (ret []byte, err error) {
	in.evm.depth++
	defer func() { in.evm.depth-- }()

	// El modo estático se hereda: una vez activado sigue en las
	// sub-llamadas y se restaura al salir de la que lo activó.
	if readOnly && !in.readOnly {
		in.readOnly = true
		defer func() { in.readOnly = false }()
	}
	// Los datos de retorno se limpian en cada llamada nueva.
	in.returnData = nil

	// Sin código no hay nada que hacer.
	if len(contract.Code) == 0 {
		return nil, nil
	}

	var (
		op    OpCode
		mem   = newMemory()
		stack = newStack()
		scope = &ScopeContext{Memory: mem, Stack: stack, Contract: contract}
		pc    = uint64(0)
		cost  uint64
		res   []byte
		hooks = in.evm.Config.Tracer
	)
	contract.Input = input
	defer func() {
		returnStack(stack)
		returnMemory(mem)
	}()

	for {
		// Cancelación externa (p.ej. timeout de eth_call).
		if in.evm.Cancelled() {
			return nil, ErrExecutionAborted
		}
		op = contract.GetOp(pc)
		operation := in.table[op]
		cost = operation.constantGas

		// Validación de pila antes de tocar nada.
		if sLen := stack.Len(); sLen < operation.minStack {
			return nil, &ErrStackUnderflow{StackLen: sLen, Required: operation.minStack}
		} else if sLen > operation.maxStack {
			return nil, &ErrStackOverflow{StackLen: sLen, Limit: operation.maxStack}
		}
		if operation.undefined {
			return nil, &ErrInvalidOpCode{Opcode: op}
		}
		if !contract.UseGas(cost) {
			return nil, ErrOutOfGas
		}

		// Gas dinámico y expansión de memoria.
		if operation.dynamicGas != nil {
			var memorySize uint64
			if operation.memorySize != nil {
				memSize, overflow := operation.memorySize(stack)
				if overflow {
					return nil, ErrGasUintOverflow
				}
				if memorySize, overflow = safeMul(toWordSize(memSize), 32); overflow {
					return nil, ErrGasUintOverflow
				}
			}
			dynamicCost, err := operation.dynamicGas(in.evm, contract, stack, mem, memorySize)
			if err != nil {
				if errors.Is(err, ErrGasUintOverflow) {
					return nil, ErrOutOfGas
				}
				return nil, err
			}
			cost += dynamicCost
			if !contract.UseGas(dynamicCost) {
				return nil, ErrOutOfGas
			}
			if memorySize > 0 {
				mem.Resize(memorySize)
			}
		}
		if hooks != nil && hooks.OnOpcode != nil {
			hooks.OnOpcode(pc, op, contract.Gas+cost, cost, scope, in.returnData, in.evm.depth, nil)
		}

		res, err = operation.execute(&pc, in, scope)
		if err != nil {
			break
		}
		pc++
	}
	if err == errStopToken {
		err = nil
	}
	return res, err
}

// ---------------------------------------------------------------------------
// Aritmética
// ---------------------------------------------------------------------------

func opAdd(_ *uint64, _ *Interpreter, s *ScopeContext) ([]byte, error) {
	x, y := s.Stack.pop(), s.Stack.peek()
	y.Add(&x, y)
	return nil, nil
}

func opSub(_ *uint64, _ *Interpreter, s *ScopeContext) ([]byte, error) {
	x, y := s.Stack.pop(), s.Stack.peek()
	y.Sub(&x, y)
	return nil, nil
}

func opMul(_ *uint64, _ *Interpreter, s *ScopeContext) ([]byte, error) {
	x, y := s.Stack.pop(), s.Stack.peek()
	y.Mul(&x, y)
	return nil, nil
}

func opDiv(_ *uint64, _ *Interpreter, s *ScopeContext) ([]byte, error) {
	x, y := s.Stack.pop(), s.Stack.peek()
	y.Div(&x, y)
	return nil, nil
}

func opSdiv(_ *uint64, _ *Interpreter, s *ScopeContext) ([]byte, error) {
	x, y := s.Stack.pop(), s.Stack.peek()
	y.SDiv(&x, y)
	return nil, nil
}

func opMod(_ *uint64, _ *Interpreter, s *ScopeContext) ([]byte, error) {
	x, y := s.Stack.pop(), s.Stack.peek()
	y.Mod(&x, y)
	return nil, nil
}

func opSmod(_ *uint64, _ *Interpreter, s *ScopeContext) ([]byte, error) {
	x, y := s.Stack.pop(), s.Stack.peek()
	y.SMod(&x, y)
	return nil, nil
}

func opAddmod(_ *uint64, _ *Interpreter, s *ScopeContext) ([]byte, error) {
	x, y, z := s.Stack.pop(), s.Stack.pop(), s.Stack.peek()
	z.AddMod(&x, &y, z)
	return nil, nil
}

func opMulmod(_ *uint64, _ *Interpreter, s *ScopeContext) ([]byte, error) {
	x, y, z := s.Stack.pop(), s.Stack.pop(), s.Stack.peek()
	z.MulMod(&x, &y, z)
	return nil, nil
}

func opExp(_ *uint64, _ *Interpreter, s *ScopeContext) ([]byte, error) {
	base, exponent := s.Stack.pop(), s.Stack.peek()
	exponent.Exp(&base, exponent)
	return nil, nil
}

func opSignExtend(_ *uint64, _ *Interpreter, s *ScopeContext) ([]byte, error) {
	back, num := s.Stack.pop(), s.Stack.peek()
	num.SignExtend(&back, num)
	return nil, nil
}

// ---------------------------------------------------------------------------
// Comparación y bits
// ---------------------------------------------------------------------------

// boolWord asigna 1 ó 0 según b.
func boolWord(z *Word, b bool) {
	if b {
		z.SetOne()
	} else {
		z.Clear()
	}
}

func opLt(_ *uint64, _ *Interpreter, s *ScopeContext) ([]byte, error) {
	x, y := s.Stack.pop(), s.Stack.peek()
	boolWord(y, x.Lt(y))
	return nil, nil
}

func opGt(_ *uint64, _ *Interpreter, s *ScopeContext) ([]byte, error) {
	x, y := s.Stack.pop(), s.Stack.peek()
	boolWord(y, x.Gt(y))
	return nil, nil
}

func opSlt(_ *uint64, _ *Interpreter, s *ScopeContext) ([]byte, error) {
	x, y := s.Stack.pop(), s.Stack.peek()
	boolWord(y, x.Slt(y))
	return nil, nil
}

func opSgt(_ *uint64, _ *Interpreter, s *ScopeContext) ([]byte, error) {
	x, y := s.Stack.pop(), s.Stack.peek()
	boolWord(y, x.Sgt(y))
	return nil, nil
}

func opEq(_ *uint64, _ *Interpreter, s *ScopeContext) ([]byte, error) {
	x, y := s.Stack.pop(), s.Stack.peek()
	boolWord(y, x.Eq(y))
	return nil, nil
}

func opIszero(_ *uint64, _ *Interpreter, s *ScopeContext) ([]byte, error) {
	x := s.Stack.peek()
	boolWord(x, x.IsZero())
	return nil, nil
}

func opAnd(_ *uint64, _ *Interpreter, s *ScopeContext) ([]byte, error) {
	x, y := s.Stack.pop(), s.Stack.peek()
	y.And(&x, y)
	return nil, nil
}

func opOr(_ *uint64, _ *Interpreter, s *ScopeContext) ([]byte, error) {
	x, y := s.Stack.pop(), s.Stack.peek()
	y.Or(&x, y)
	return nil, nil
}

func opXor(_ *uint64, _ *Interpreter, s *ScopeContext) ([]byte, error) {
	x, y := s.Stack.pop(), s.Stack.peek()
	y.Xor(&x, y)
	return nil, nil
}

func opNot(_ *uint64, _ *Interpreter, s *ScopeContext) ([]byte, error) {
	x := s.Stack.peek()
	x.Not(x)
	return nil, nil
}

func opByte(_ *uint64, _ *Interpreter, s *ScopeContext) ([]byte, error) {
	th, val := s.Stack.pop(), s.Stack.peek()
	val.Byte(&th, val)
	return nil, nil
}

// shiftAmount convierte el operando de desplazamiento (>= 256 satura).
func shiftAmount(w *Word) uint {
	if !w.IsUint64() || w[0] >= 256 {
		return 256
	}
	return uint(w[0])
}

func opSHL(_ *uint64, _ *Interpreter, s *ScopeContext) ([]byte, error) {
	shift, value := s.Stack.pop(), s.Stack.peek()
	value.Lsh(value, shiftAmount(&shift))
	return nil, nil
}

func opSHR(_ *uint64, _ *Interpreter, s *ScopeContext) ([]byte, error) {
	shift, value := s.Stack.pop(), s.Stack.peek()
	value.Rsh(value, shiftAmount(&shift))
	return nil, nil
}

func opSAR(_ *uint64, _ *Interpreter, s *ScopeContext) ([]byte, error) {
	shift, value := s.Stack.pop(), s.Stack.peek()
	value.SRsh(value, shiftAmount(&shift))
	return nil, nil
}

// opKeccak256 hashea un rango de memoria.
func opKeccak256(_ *uint64, in *Interpreter, s *ScopeContext) ([]byte, error) {
	offset, size := s.Stack.pop(), s.Stack.peek()
	data := s.Memory.GetPtr(offset.Uint64(), size.Uint64())
	size.SetBytes(types.Keccak256(data))
	return nil, nil
}

// ---------------------------------------------------------------------------
// Pila, memoria y control de flujo
// ---------------------------------------------------------------------------

func opPop(_ *uint64, _ *Interpreter, s *ScopeContext) ([]byte, error) {
	s.Stack.pop()
	return nil, nil
}

func opMload(_ *uint64, _ *Interpreter, s *ScopeContext) ([]byte, error) {
	v := s.Stack.peek()
	off := v.Uint64()
	v.SetBytes(s.Memory.GetPtr(off, 32))
	return nil, nil
}

func opMstore(_ *uint64, _ *Interpreter, s *ScopeContext) ([]byte, error) {
	off, val := s.Stack.pop(), s.Stack.pop()
	s.Memory.Set32(off.Uint64(), &val)
	return nil, nil
}

func opMstore8(_ *uint64, _ *Interpreter, s *ScopeContext) ([]byte, error) {
	off, val := s.Stack.pop(), s.Stack.pop()
	s.Memory.SetByte(off.Uint64(), byte(val[0]))
	return nil, nil
}

func opMcopy(_ *uint64, _ *Interpreter, s *ScopeContext) ([]byte, error) {
	dst, src, length := s.Stack.pop(), s.Stack.pop(), s.Stack.pop()
	// El gas ya garantizó que dst+len y src+len caben en memoria.
	s.Memory.Copy(dst.Uint64(), src.Uint64(), length.Uint64())
	return nil, nil
}

func opJump(pc *uint64, in *Interpreter, s *ScopeContext) ([]byte, error) {
	if in.evm.Cancelled() {
		return nil, errStopToken
	}
	pos := s.Stack.pop()
	if !s.Contract.validJumpdest(&pos) {
		return nil, ErrInvalidJump
	}
	*pc = pos.Uint64() - 1 // el bucle incrementa pc después
	return nil, nil
}

func opJumpi(pc *uint64, in *Interpreter, s *ScopeContext) ([]byte, error) {
	if in.evm.Cancelled() {
		return nil, errStopToken
	}
	pos, cond := s.Stack.pop(), s.Stack.pop()
	if !cond.IsZero() {
		if !s.Contract.validJumpdest(&pos) {
			return nil, ErrInvalidJump
		}
		*pc = pos.Uint64() - 1
	}
	return nil, nil
}

func opJumpdest(_ *uint64, _ *Interpreter, _ *ScopeContext) ([]byte, error) { return nil, nil }

func opPc(pc *uint64, _ *Interpreter, s *ScopeContext) ([]byte, error) {
	s.Stack.push(NewWord(*pc))
	return nil, nil
}

func opMsize(_ *uint64, _ *Interpreter, s *ScopeContext) ([]byte, error) {
	s.Stack.push(NewWord(uint64(s.Memory.Len())))
	return nil, nil
}

func opGas(_ *uint64, _ *Interpreter, s *ScopeContext) ([]byte, error) {
	s.Stack.push(NewWord(s.Contract.Gas))
	return nil, nil
}

func opPush0(_ *uint64, _ *Interpreter, s *ScopeContext) ([]byte, error) {
	s.Stack.push(new(Word))
	return nil, nil
}

// makePush crea la implementación de PUSHn: lee n bytes inmediatos
// (rellenando con ceros a la derecha si el código termina antes).
func makePush(n uint64) executionFunc {
	return func(pc *uint64, _ *Interpreter, s *ScopeContext) ([]byte, error) {
		code := s.Contract.Code
		start := min(*pc+1, uint64(len(code)))
		end := min(start+n, uint64(len(code)))
		var buf [32]byte
		copy(buf[32-n:], code[start:end]) // bytes ausentes quedan a 0 al final
		var w Word
		// Si faltaron bytes, los presentes ocupan la parte alta del valor
		// de n bytes (el resto son ceros a la derecha, como en Ethereum).
		w.SetBytes(buf[32-n:])
		s.Stack.push(&w)
		*pc += n
		return nil, nil
	}
}

// makeDup crea DUPn.
func makeDup(n int) executionFunc {
	return func(_ *uint64, _ *Interpreter, s *ScopeContext) ([]byte, error) {
		s.Stack.dup(n)
		return nil, nil
	}
}

// makeSwap crea SWAPn.
func makeSwap(n int) executionFunc {
	return func(_ *uint64, _ *Interpreter, s *ScopeContext) ([]byte, error) {
		s.Stack.swap(n)
		return nil, nil
	}
}

func opStop(_ *uint64, _ *Interpreter, _ *ScopeContext) ([]byte, error) {
	return nil, errStopToken
}

func opReturn(_ *uint64, _ *Interpreter, s *ScopeContext) ([]byte, error) {
	off, size := s.Stack.pop(), s.Stack.pop()
	return s.Memory.GetCopy(off.Uint64(), size.Uint64()), errStopToken
}

func opRevert(_ *uint64, in *Interpreter, s *ScopeContext) ([]byte, error) {
	off, size := s.Stack.pop(), s.Stack.pop()
	ret := s.Memory.GetCopy(off.Uint64(), size.Uint64())
	in.returnData = ret
	return ret, ErrExecutionReverted
}

func opInvalid(_ *uint64, _ *Interpreter, _ *ScopeContext) ([]byte, error) {
	return nil, &ErrInvalidOpCode{Opcode: INVALID}
}

// ---------------------------------------------------------------------------
// Tabla de saltos
// ---------------------------------------------------------------------------

// defaultJumpTable es la tabla de la cadena (reglas tipo Cancún).
var defaultJumpTable = newJumpTable()

// newJumpTable construye la tabla completa. Los opcodes no listados quedan
// marcados como indefinidos (fallan con ErrInvalidOpCode).
func newJumpTable() JumpTable {
	var t JumpTable
	set := func(op OpCode, o operation) { oo := o; t[op] = &oo }
	simple := func(op OpCode, f executionFunc, gas uint64, pops, pushes int) {
		set(op, operation{execute: f, constantGas: gas, minStack: minStack(pops, pushes), maxStack: maxStack(pops, pushes)})
	}

	set(STOP, operation{execute: opStop, minStack: 0, maxStack: StackLimit})
	simple(ADD, opAdd, GasFastestStep, 2, 1)
	simple(MUL, opMul, GasFastStep, 2, 1)
	simple(SUB, opSub, GasFastestStep, 2, 1)
	simple(DIV, opDiv, GasFastStep, 2, 1)
	simple(SDIV, opSdiv, GasFastStep, 2, 1)
	simple(MOD, opMod, GasFastStep, 2, 1)
	simple(SMOD, opSmod, GasFastStep, 2, 1)
	simple(ADDMOD, opAddmod, GasMidStep, 3, 1)
	simple(MULMOD, opMulmod, GasMidStep, 3, 1)
	set(EXP, operation{execute: opExp, constantGas: ExpGas, dynamicGas: gasExp, minStack: 2, maxStack: maxStack(2, 1)})
	simple(SIGNEXTEND, opSignExtend, GasFastStep, 2, 1)

	simple(LT, opLt, GasFastestStep, 2, 1)
	simple(GT, opGt, GasFastestStep, 2, 1)
	simple(SLT, opSlt, GasFastestStep, 2, 1)
	simple(SGT, opSgt, GasFastestStep, 2, 1)
	simple(EQ, opEq, GasFastestStep, 2, 1)
	simple(ISZERO, opIszero, GasFastestStep, 1, 1)
	simple(AND, opAnd, GasFastestStep, 2, 1)
	simple(OR, opOr, GasFastestStep, 2, 1)
	simple(XOR, opXor, GasFastestStep, 2, 1)
	simple(NOT, opNot, GasFastestStep, 1, 1)
	simple(BYTE, opByte, GasFastestStep, 2, 1)
	simple(SHL, opSHL, GasFastestStep, 2, 1)
	simple(SHR, opSHR, GasFastestStep, 2, 1)
	simple(SAR, opSAR, GasFastestStep, 2, 1)

	set(KECCAK256, operation{execute: opKeccak256, constantGas: Keccak256Gas, dynamicGas: gasKeccak256,
		minStack: 2, maxStack: maxStack(2, 1), memorySize: memoryKeccak256})

	// Entorno (implementaciones en evm_context.go).
	simple(ADDRESS, opAddress, GasQuickStep, 0, 1)
	set(BALANCE, operation{execute: opBalance, constantGas: WarmStorageReadCost, dynamicGas: gasAccountAccess, minStack: 1, maxStack: maxStack(1, 1)})
	simple(ORIGIN, opOrigin, GasQuickStep, 0, 1)
	simple(CALLER, opCaller, GasQuickStep, 0, 1)
	simple(CALLVALUE, opCallValue, GasQuickStep, 0, 1)
	simple(CALLDATALOAD, opCallDataLoad, GasFastestStep, 1, 1)
	simple(CALLDATASIZE, opCallDataSize, GasQuickStep, 0, 1)
	set(CALLDATACOPY, operation{execute: opCallDataCopy, constantGas: GasFastestStep, dynamicGas: gasCallDataCopy,
		minStack: 3, maxStack: maxStack(3, 0), memorySize: memoryCallDataCopy})
	simple(CODESIZE, opCodeSize, GasQuickStep, 0, 1)
	set(CODECOPY, operation{execute: opCodeCopy, constantGas: GasFastestStep, dynamicGas: gasCodeCopy,
		minStack: 3, maxStack: maxStack(3, 0), memorySize: memoryCodeCopy})
	simple(GASPRICE, opGasprice, GasQuickStep, 0, 1)
	set(EXTCODESIZE, operation{execute: opExtCodeSize, constantGas: WarmStorageReadCost, dynamicGas: gasAccountAccess, minStack: 1, maxStack: maxStack(1, 1)})
	set(EXTCODECOPY, operation{execute: opExtCodeCopy, constantGas: WarmStorageReadCost, dynamicGas: gasExtCodeCopy,
		minStack: 4, maxStack: maxStack(4, 0), memorySize: memoryExtCodeCopy})
	simple(RETURNDATASIZE, opReturnDataSize, GasQuickStep, 0, 1)
	set(RETURNDATACOPY, operation{execute: opReturnDataCopy, constantGas: GasFastestStep, dynamicGas: gasReturnDataCopy,
		minStack: 3, maxStack: maxStack(3, 0), memorySize: memoryReturnDataCopy})
	set(EXTCODEHASH, operation{execute: opExtCodeHash, constantGas: WarmStorageReadCost, dynamicGas: gasAccountAccess, minStack: 1, maxStack: maxStack(1, 1)})

	simple(BLOCKHASH, opBlockhash, BlockhashGas, 1, 1)
	simple(COINBASE, opCoinbase, GasQuickStep, 0, 1)
	simple(TIMESTAMP, opTimestamp, GasQuickStep, 0, 1)
	simple(NUMBER, opNumber, GasQuickStep, 0, 1)
	simple(PREVRANDAO, opRandom, GasQuickStep, 0, 1)
	simple(GASLIMIT, opGasLimit, GasQuickStep, 0, 1)
	simple(CHAINID, opChainID, GasQuickStep, 0, 1)
	simple(SELFBALANCE, opSelfBalance, GasFastStep, 0, 1)
	simple(BASEFEE, opBaseFee, GasQuickStep, 0, 1)
	simple(BLOBHASH, opBlobHash, GasFastestStep, 1, 1)
	simple(BLOBBASEFEE, opBlobBaseFee, GasQuickStep, 0, 1)

	simple(POP, opPop, GasQuickStep, 1, 0)
	set(MLOAD, operation{execute: opMload, constantGas: GasFastestStep, dynamicGas: pureMemoryGascost,
		minStack: 1, maxStack: maxStack(1, 1), memorySize: memoryMLoad})
	set(MSTORE, operation{execute: opMstore, constantGas: GasFastestStep, dynamicGas: pureMemoryGascost,
		minStack: 2, maxStack: maxStack(2, 0), memorySize: memoryMStore})
	set(MSTORE8, operation{execute: opMstore8, constantGas: GasFastestStep, dynamicGas: pureMemoryGascost,
		minStack: 2, maxStack: maxStack(2, 0), memorySize: memoryMStore8})
	// Almacenamiento (storage_ops.go).
	set(SLOAD, operation{execute: opSload, dynamicGas: gasSLoad, minStack: 1, maxStack: maxStack(1, 1)})
	set(SSTORE, operation{execute: opSstore, dynamicGas: gasSStore, minStack: 2, maxStack: maxStack(2, 0)})
	simple(JUMP, opJump, GasMidStep, 1, 0)
	simple(JUMPI, opJumpi, GasSlowStep, 2, 0)
	simple(PC, opPc, GasQuickStep, 0, 1)
	simple(MSIZE, opMsize, GasQuickStep, 0, 1)
	simple(GAS, opGas, GasQuickStep, 0, 1)
	simple(JUMPDEST, opJumpdest, JumpdestGas, 0, 0)
	simple(TLOAD, opTload, TloadGas, 1, 1)
	simple(TSTORE, opTstore, TstoreGas, 2, 0)
	set(MCOPY, operation{execute: opMcopy, constantGas: GasFastestStep, dynamicGas: gasMcopy,
		minStack: 3, maxStack: maxStack(3, 0), memorySize: memoryMcopy})
	simple(PUSH0, opPush0, GasQuickStep, 0, 1)

	for i := 0; i < 32; i++ {
		simple(PUSH1+OpCode(i), makePush(uint64(i+1)), GasFastestStep, 0, 1)
	}
	for i := 1; i <= 16; i++ {
		simple(DUP1+OpCode(i-1), makeDup(i), GasFastestStep, i, i+1)
		simple(SWAP1+OpCode(i-1), makeSwap(i), GasFastestStep, i+1, i+1)
	}
	// Registros (logs_events.go).
	for n := 0; n <= 4; n++ {
		set(LOG0+OpCode(n), operation{execute: makeLog(n), constantGas: LogGas, dynamicGas: makeGasLog(uint64(n)),
			minStack: 2 + n, maxStack: maxStack(2+n, 0), memorySize: memoryLog})
	}

	// Creación y llamadas (contract_create.go, contract_call.go).
	set(CREATE, operation{execute: opCreate, constantGas: CreateGas, dynamicGas: gasCreate,
		minStack: 3, maxStack: maxStack(3, 1), memorySize: memoryCreate})
	set(CREATE2, operation{execute: opCreate2, constantGas: CreateGas, dynamicGas: gasCreate2,
		minStack: 4, maxStack: maxStack(4, 1), memorySize: memoryCreate2})
	set(CALL, operation{execute: opCall, constantGas: WarmStorageReadCost, dynamicGas: gasCall,
		minStack: 7, maxStack: maxStack(7, 1), memorySize: memoryCall})
	set(CALLCODE, operation{execute: opCallCode, constantGas: WarmStorageReadCost, dynamicGas: gasCallCode,
		minStack: 7, maxStack: maxStack(7, 1), memorySize: memoryCall})
	set(DELEGATECALL, operation{execute: opDelegateCall, constantGas: WarmStorageReadCost, dynamicGas: gasDelegateCall,
		minStack: 6, maxStack: maxStack(6, 1), memorySize: memoryDelegateCall})
	set(STATICCALL, operation{execute: opStaticCall, constantGas: WarmStorageReadCost, dynamicGas: gasStaticCall,
		minStack: 6, maxStack: maxStack(6, 1), memorySize: memoryDelegateCall})
	set(RETURN, operation{execute: opReturn, dynamicGas: pureMemoryGascost, minStack: 2, maxStack: maxStack(2, 0), memorySize: memoryReturn})
	set(REVERT, operation{execute: opRevert, dynamicGas: pureMemoryGascost, minStack: 2, maxStack: maxStack(2, 0), memorySize: memoryRevert})
	set(INVALID, operation{execute: opInvalid, minStack: 0, maxStack: StackLimit})
	set(SELFDESTRUCT, operation{execute: opSelfdestruct, constantGas: SelfdestructGas, dynamicGas: gasSelfdestruct,
		minStack: 1, maxStack: maxStack(1, 0)})

	// Rellenamos los huecos con operaciones indefinidas.
	for i := range t {
		if t[i] == nil {
			t[i] = &operation{execute: opInvalid, maxStack: StackLimit, undefined: true}
		}
	}
	return t
}
