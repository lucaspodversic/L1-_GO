package execution

// Este archivo enumera los códigos de operación (opcodes) de la EVM con sus
// nombres mnemónicos. El valor numérico de cada opcode coincide con el de
// Ethereum para que el bytecode compilado con solc/vyper funcione sin cambios.

import "fmt"

// OpCode es un byte de instrucción de la EVM.
type OpCode byte

// 0x00 - 0x0b: aritmética.
const (
	STOP       OpCode = 0x00
	ADD        OpCode = 0x01
	MUL        OpCode = 0x02
	SUB        OpCode = 0x03
	DIV        OpCode = 0x04
	SDIV       OpCode = 0x05
	MOD        OpCode = 0x06
	SMOD       OpCode = 0x07
	ADDMOD     OpCode = 0x08
	MULMOD     OpCode = 0x09
	EXP        OpCode = 0x0a
	SIGNEXTEND OpCode = 0x0b
)

// 0x10 - 0x1d: comparación y operaciones de bits.
const (
	LT     OpCode = 0x10
	GT     OpCode = 0x11
	SLT    OpCode = 0x12
	SGT    OpCode = 0x13
	EQ     OpCode = 0x14
	ISZERO OpCode = 0x15
	AND    OpCode = 0x16
	OR     OpCode = 0x17
	XOR    OpCode = 0x18
	NOT    OpCode = 0x19
	BYTE   OpCode = 0x1a
	SHL    OpCode = 0x1b
	SHR    OpCode = 0x1c
	SAR    OpCode = 0x1d
)

// 0x20: hash.
const KECCAK256 OpCode = 0x20

// 0x30 - 0x3f: información del entorno de ejecución.
const (
	ADDRESS        OpCode = 0x30
	BALANCE        OpCode = 0x31
	ORIGIN         OpCode = 0x32
	CALLER         OpCode = 0x33
	CALLVALUE      OpCode = 0x34
	CALLDATALOAD   OpCode = 0x35
	CALLDATASIZE   OpCode = 0x36
	CALLDATACOPY   OpCode = 0x37
	CODESIZE       OpCode = 0x38
	CODECOPY       OpCode = 0x39
	GASPRICE       OpCode = 0x3a
	EXTCODESIZE    OpCode = 0x3b
	EXTCODECOPY    OpCode = 0x3c
	RETURNDATASIZE OpCode = 0x3d
	RETURNDATACOPY OpCode = 0x3e
	EXTCODEHASH    OpCode = 0x3f
)

// 0x40 - 0x4a: información del bloque.
const (
	BLOCKHASH   OpCode = 0x40
	COINBASE    OpCode = 0x41
	TIMESTAMP   OpCode = 0x42
	NUMBER      OpCode = 0x43
	PREVRANDAO  OpCode = 0x44 // antes DIFFICULTY
	GASLIMIT    OpCode = 0x45
	CHAINID     OpCode = 0x46
	SELFBALANCE OpCode = 0x47
	BASEFEE     OpCode = 0x48
	BLOBHASH    OpCode = 0x49 // sin blobs: siempre devuelve 0
	BLOBBASEFEE OpCode = 0x4a // sin blobs: devuelve 1 (mínimo de EIP-4844)
)

// 0x50 - 0x5f: pila, memoria, almacenamiento y flujo de control.
const (
	POP      OpCode = 0x50
	MLOAD    OpCode = 0x51
	MSTORE   OpCode = 0x52
	MSTORE8  OpCode = 0x53
	SLOAD    OpCode = 0x54
	SSTORE   OpCode = 0x55
	JUMP     OpCode = 0x56
	JUMPI    OpCode = 0x57
	PC       OpCode = 0x58
	MSIZE    OpCode = 0x59
	GAS      OpCode = 0x5a
	JUMPDEST OpCode = 0x5b
	TLOAD    OpCode = 0x5c // EIP-1153
	TSTORE   OpCode = 0x5d // EIP-1153
	MCOPY    OpCode = 0x5e // EIP-5656
	PUSH0    OpCode = 0x5f // EIP-3855
)

// 0x60 - 0x7f: PUSH1..PUSH32. Los valores intermedios se calculan como
// PUSH1 + (n-1).
const (
	PUSH1  OpCode = 0x60
	PUSH32 OpCode = 0x7f
)

// 0x80 - 0x8f: DUP1..DUP16; 0x90 - 0x9f: SWAP1..SWAP16.
const (
	DUP1   OpCode = 0x80
	DUP16  OpCode = 0x8f
	SWAP1  OpCode = 0x90
	SWAP16 OpCode = 0x9f
)

// 0xa0 - 0xa4: registros (eventos).
const (
	LOG0 OpCode = 0xa0
	LOG1 OpCode = 0xa1
	LOG2 OpCode = 0xa2
	LOG3 OpCode = 0xa3
	LOG4 OpCode = 0xa4
)

// 0xf0 - 0xff: llamadas, creación y terminación.
const (
	CREATE       OpCode = 0xf0
	CALL         OpCode = 0xf1
	CALLCODE     OpCode = 0xf2
	RETURN       OpCode = 0xf3
	DELEGATECALL OpCode = 0xf4
	CREATE2      OpCode = 0xf5
	STATICCALL   OpCode = 0xfa
	REVERT       OpCode = 0xfd
	INVALID      OpCode = 0xfe
	SELFDESTRUCT OpCode = 0xff
)

// opNames asocia cada opcode definido con su mnemónico. Se rellena en init
// para los rangos PUSH/DUP/SWAP/LOG.
var opNames = map[OpCode]string{
	STOP: "STOP", ADD: "ADD", MUL: "MUL", SUB: "SUB", DIV: "DIV", SDIV: "SDIV",
	MOD: "MOD", SMOD: "SMOD", ADDMOD: "ADDMOD", MULMOD: "MULMOD", EXP: "EXP",
	SIGNEXTEND: "SIGNEXTEND",
	LT:         "LT", GT: "GT", SLT: "SLT", SGT: "SGT", EQ: "EQ", ISZERO: "ISZERO",
	AND: "AND", OR: "OR", XOR: "XOR", NOT: "NOT", BYTE: "BYTE", SHL: "SHL",
	SHR: "SHR", SAR: "SAR",
	KECCAK256: "KECCAK256",
	ADDRESS:   "ADDRESS", BALANCE: "BALANCE", ORIGIN: "ORIGIN", CALLER: "CALLER",
	CALLVALUE: "CALLVALUE", CALLDATALOAD: "CALLDATALOAD", CALLDATASIZE: "CALLDATASIZE",
	CALLDATACOPY: "CALLDATACOPY", CODESIZE: "CODESIZE", CODECOPY: "CODECOPY",
	GASPRICE: "GASPRICE", EXTCODESIZE: "EXTCODESIZE", EXTCODECOPY: "EXTCODECOPY",
	RETURNDATASIZE: "RETURNDATASIZE", RETURNDATACOPY: "RETURNDATACOPY",
	EXTCODEHASH: "EXTCODEHASH",
	BLOCKHASH:   "BLOCKHASH", COINBASE: "COINBASE", TIMESTAMP: "TIMESTAMP",
	NUMBER: "NUMBER", PREVRANDAO: "PREVRANDAO", GASLIMIT: "GASLIMIT",
	CHAINID: "CHAINID", SELFBALANCE: "SELFBALANCE", BASEFEE: "BASEFEE",
	BLOBHASH: "BLOBHASH", BLOBBASEFEE: "BLOBBASEFEE",
	POP: "POP", MLOAD: "MLOAD", MSTORE: "MSTORE", MSTORE8: "MSTORE8",
	SLOAD: "SLOAD", SSTORE: "SSTORE", JUMP: "JUMP", JUMPI: "JUMPI", PC: "PC",
	MSIZE: "MSIZE", GAS: "GAS", JUMPDEST: "JUMPDEST", TLOAD: "TLOAD",
	TSTORE: "TSTORE", MCOPY: "MCOPY", PUSH0: "PUSH0",
	CREATE: "CREATE", CALL: "CALL", CALLCODE: "CALLCODE", RETURN: "RETURN",
	DELEGATECALL: "DELEGATECALL", CREATE2: "CREATE2", STATICCALL: "STATICCALL",
	REVERT: "REVERT", INVALID: "INVALID", SELFDESTRUCT: "SELFDESTRUCT",
}

// opByName es el índice inverso de opNames (útil para ensambladores).
var opByName = map[string]OpCode{}

func init() {
	for i := 0; i < 32; i++ {
		opNames[PUSH1+OpCode(i)] = fmt.Sprintf("PUSH%d", i+1)
	}
	for i := 0; i < 16; i++ {
		opNames[DUP1+OpCode(i)] = fmt.Sprintf("DUP%d", i+1)
		opNames[SWAP1+OpCode(i)] = fmt.Sprintf("SWAP%d", i+1)
	}
	for i := 0; i <= 4; i++ {
		opNames[LOG0+OpCode(i)] = fmt.Sprintf("LOG%d", i)
	}
	for op, name := range opNames {
		opByName[name] = op
	}
}

// String devuelve el mnemónico del opcode, o una representación hexadecimal
// si no está definido.
func (op OpCode) String() string {
	if s, ok := opNames[op]; ok {
		return s
	}
	return fmt.Sprintf("opcode 0x%02x no definido", byte(op))
}

// IsPush informa si el opcode es PUSH1..PUSH32 (PUSH0 no lleva datos
// inmediatos, por eso no cuenta).
func (op OpCode) IsPush() bool { return op >= PUSH1 && op <= PUSH32 }

// PushSize devuelve cuántos bytes inmediatos lee un PUSHn (0 si no es PUSH).
func (op OpCode) PushSize() int {
	if !op.IsPush() {
		return 0
	}
	return int(op-PUSH1) + 1
}

// StringToOp convierte un mnemónico en opcode.
func StringToOp(s string) (OpCode, bool) {
	op, ok := opByName[s]
	return op, ok
}

// Assemble es un mini-ensamblador para pruebas y herramientas: recibe
// mnemónicos y bytes inmediatos ya codificados. Cada elemento puede ser un
// OpCode, un byte suelto o un []byte (datos de PUSH).
//
// Ejemplo: Assemble(PUSH1, byte(2), PUSH1, byte(3), ADD) => 0x6002600301.
func Assemble(parts ...any) []byte {
	var out []byte
	for _, p := range parts {
		switch v := p.(type) {
		case OpCode:
			out = append(out, byte(v))
		case byte:
			out = append(out, v)
		case int:
			out = append(out, byte(v))
		case []byte:
			out = append(out, v...)
		default:
			panic(fmt.Sprintf("execution: Assemble: tipo no soportado %T", p))
		}
	}
	return out
}
