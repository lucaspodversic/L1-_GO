package execution

// Este archivo define Contract, el marco de una llamada: qué código se
// ejecuta, en nombre de qué cuenta, con qué datos de entrada, valor y gas.
// También contiene el análisis de destinos de salto (JUMPDEST) que impide
// saltar al interior de los datos inmediatos de un PUSH.

import (
	"sync"

	"github.com/l1/l1/types"
)

// bitvec es un mapa de bits: el bit i a 1 indica que el byte i del código es
// dato de un PUSH (y por tanto no puede ser un JUMPDEST válido).
type bitvec []byte

// set1 marca la posición pos como dato.
func (b bitvec) set1(pos uint64) { b[pos/8] |= 1 << (pos % 8) }

// isCode informa si pos es código (no dato de PUSH).
func (b bitvec) isCode(pos uint64) bool { return b[pos/8]&(1<<(pos%8)) == 0 }

// codeBitmap analiza el código y marca los bytes de datos de los PUSH.
func codeBitmap(code []byte) bitvec {
	// Reservamos 4 bytes extra: un PUSH32 al final puede marcar posiciones
	// más allá del código.
	bits := make(bitvec, len(code)/8+1+4)
	for pc := uint64(0); pc < uint64(len(code)); {
		op := OpCode(code[pc])
		pc++
		if n := op.PushSize(); n > 0 {
			for i := 0; i < n; i++ {
				bits.set1(pc + uint64(i))
			}
			pc += uint64(n)
		}
	}
	return bits
}

// analysisCache memoriza el análisis por hash de código: los contratos más
// usados (tokens, routers) se ejecutan muchas veces por bloque.
var analysisCache sync.Map // types.Hash -> bitvec

// Contract es el marco de ejecución de una llamada.
type Contract struct {
	// caller es quien invoca (msg.sender dentro del código).
	caller types.Address
	// address es la cuenta cuyo contexto (almacenamiento, saldo) se usa.
	address types.Address

	// Code es el bytecode que se ejecuta y CodeHash su hash (cero si el
	// código no está en el estado, p.ej. initcode de CREATE).
	Code     []byte
	CodeHash types.Hash
	// CodeAddr es la cuenta de la que procede el código (difiere de
	// address en CALLCODE/DELEGATECALL).
	CodeAddr *types.Address
	// Input son los datos de la llamada (calldata).
	Input []byte

	// Gas es el gas restante del marco.
	Gas uint64
	// value es el valor transferido (msg.value).
	value *Word

	// IsDeployment indica que el marco ejecuta initcode.
	IsDeployment bool

	analysis bitvec // análisis de JUMPDEST, calculado bajo demanda
}

// NewContract crea un marco nuevo.
func NewContract(caller, address types.Address, value *Word, gas uint64) *Contract {
	if value == nil {
		value = new(Word)
	}
	return &Contract{caller: caller, address: address, value: value, Gas: gas}
}

// Caller devuelve msg.sender.
func (c *Contract) Caller() types.Address { return c.caller }

// Address devuelve la cuenta en cuyo contexto se ejecuta.
func (c *Contract) Address() types.Address { return c.address }

// Value devuelve msg.value.
func (c *Contract) Value() *Word { return c.value }

// SetCallCode asigna el código a ejecutar.
func (c *Contract) SetCallCode(addr *types.Address, hash types.Hash, code []byte) {
	c.Code, c.CodeHash, c.CodeAddr = code, hash, addr
}

// GetOp devuelve el opcode en la posición n; fuera del código es STOP
// (semántica de la EVM: el código está implícitamente seguido de ceros).
func (c *Contract) GetOp(n uint64) OpCode {
	if n < uint64(len(c.Code)) {
		return OpCode(c.Code[n])
	}
	return STOP
}

// UseGas descuenta gas e informa si había suficiente.
func (c *Contract) UseGas(gas uint64) bool {
	if c.Gas < gas {
		return false
	}
	c.Gas -= gas
	return true
}

// RefundGas devuelve gas no consumido por una sub-llamada.
func (c *Contract) RefundGas(gas uint64) { c.Gas += gas }

// validJumpdest informa si dest es un destino de salto válido: debe estar
// dentro del código, ser un JUMPDEST y no formar parte de un PUSH.
func (c *Contract) validJumpdest(dest *Word) bool {
	udest, overflow := dest.Uint64WithOverflow()
	if overflow || udest >= uint64(len(c.Code)) {
		return false
	}
	if OpCode(c.Code[udest]) != JUMPDEST {
		return false
	}
	return c.isCode(udest)
}

// isCode consulta (y calcula si hace falta) el análisis de saltos.
func (c *Contract) isCode(udest uint64) bool {
	if c.analysis == nil {
		if !c.CodeHash.IsZero() {
			if v, ok := analysisCache.Load(c.CodeHash); ok {
				c.analysis = v.(bitvec)
			} else {
				c.analysis = codeBitmap(c.Code)
				analysisCache.Store(c.CodeHash, c.analysis)
			}
		} else {
			// Initcode: no se cachea (no tiene hash en el estado).
			c.analysis = codeBitmap(c.Code)
		}
	}
	return c.analysis.isCode(udest)
}

// ScopeContext agrupa el estado de un marco que manipulan las instrucciones.
type ScopeContext struct {
	Memory   *Memory
	Stack    *Stack
	Contract *Contract
}

// MemoryData devuelve la memoria (para trazadores).
func (s *ScopeContext) MemoryData() []byte { return s.Memory.Data() }

// StackData devuelve la pila (para trazadores).
func (s *ScopeContext) StackData() []Word { return s.Stack.Data() }

// Caller devuelve msg.sender del marco.
func (s *ScopeContext) Caller() types.Address { return s.Contract.Caller() }

// Address devuelve la cuenta del marco.
func (s *ScopeContext) Address() types.Address { return s.Contract.Address() }

// CallValue devuelve msg.value del marco.
func (s *ScopeContext) CallValue() *Word { return s.Contract.Value() }

// CallInput devuelve el calldata del marco.
func (s *ScopeContext) CallInput() []byte { return s.Contract.Input }
