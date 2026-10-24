package execution

// Este archivo define el contexto que la EVM necesita del bloque y de la
// transacción en curso (coinbase, número, marca de tiempo, base fee, origen,
// precio del gas...) y las instrucciones que lo exponen al bytecode
// (ADDRESS, CALLER, NUMBER, BASEFEE, ...).

import (
	"github.com/l1/l1/types"
)

// ChainConfig agrupa la configuración de la cadena relevante para ejecutar.
type ChainConfig struct {
	// ChainID es el identificador EIP-155 (opcode CHAINID).
	ChainID types.ChainID
	// Fees configura el destino de la base fee y otros parámetros del
	// mercado de comisiones.
	Fees FeeConfig
	// SystemContracts añade (o sustituye) contratos nativos además de los
	// estándar; lo usa el consenso para registrar p. ej. el contrato de
	// evidencias de slashing sin crear un ciclo de imports.
	SystemContracts map[types.Address]SystemContract
}

// DefaultChainConfig devuelve una configuración con valores por defecto.
func DefaultChainConfig(id types.ChainID) *ChainConfig {
	return &ChainConfig{ChainID: id, Fees: DefaultFeeConfig()}
}

// CanTransferFunc comprueba si una cuenta tiene saldo suficiente.
type CanTransferFunc func(db StateDB, addr types.Address, amount *Word) bool

// TransferFunc mueve valor entre cuentas.
type TransferFunc func(db StateDB, from, to types.Address, amount *Word) error

// GetHashFunc devuelve el hash del bloque con el número indicado (o cero).
type GetHashFunc func(number uint64) types.Hash

// BlockContext es la información del bloque visible para los contratos.
// Es constante durante todo el bloque.
type BlockContext struct {
	CanTransfer CanTransferFunc
	Transfer    TransferFunc
	GetHash     GetHashFunc

	Coinbase    types.Address // proponente: recibe las propinas
	GasLimit    uint64
	BlockNumber uint64
	Time        uint64 // segundos Unix
	Random      types.Hash
	BaseFee     types.Amount
	// Epoch y View exponen datos del consenso (útiles para contratos de
	// sistema; no hay opcode que los lea).
	Epoch, View uint64
}

// TxContext es la información de la transacción visible para los
// contratos; cambia en cada transacción del bloque.
type TxContext struct {
	Origin   types.Address // tx.origin
	GasPrice types.Amount  // precio efectivo por unidad de gas
}

// NewEVMBlockContext construye el contexto a partir de la cabecera. El
// coinbase es header.Proposer salvo que se indique author.
func NewEVMBlockContext(header *types.Header, getHash GetHashFunc, author *types.Address) BlockContext {
	coinbase := header.Proposer
	if author != nil {
		coinbase = *author
	}
	if getHash == nil {
		getHash = func(uint64) types.Hash { return types.Hash{} }
	}
	return BlockContext{
		CanTransfer: CanTransfer,
		Transfer:    Transfer,
		GetHash:     getHash,
		Coinbase:    coinbase,
		GasLimit:    header.GasLimit,
		BlockNumber: header.Number,
		Time:        header.Timestamp,
		Random:      header.Random,
		BaseFee:     header.BaseFee,
		Epoch:       header.Epoch,
		View:        header.View,
	}
}

// NewEVMTxContext construye el contexto de transacción.
func NewEVMTxContext(origin types.Address, gasPrice types.Amount) TxContext {
	return TxContext{Origin: origin, GasPrice: gasPrice}
}

// GetHashFromReader adapta un lector de cabeceras por número a GetHashFunc,
// respetando la ventana de 256 bloques de BLOCKHASH. current es el número
// del bloque que se está ejecutando.
func GetHashFromReader(r HeaderByNumberReader) GetHashFunc {
	return func(n uint64) types.Hash {
		h, err := r.HeaderByNumber(n)
		if err != nil || h == nil {
			return types.Hash{}
		}
		return h.Hash()
	}
}

// ---------------------------------------------------------------------------
// Instrucciones de entorno
// ---------------------------------------------------------------------------

func opAddress(_ *uint64, _ *Interpreter, s *ScopeContext) ([]byte, error) {
	s.Stack.push(new(Word).SetAddress(s.Contract.Address()))
	return nil, nil
}

func opBalance(_ *uint64, in *Interpreter, s *ScopeContext) ([]byte, error) {
	slot := s.Stack.peek()
	slot.Set(WordFromAmount(in.evm.StateDB.GetBalance(slot.Address())))
	return nil, nil
}

func opOrigin(_ *uint64, in *Interpreter, s *ScopeContext) ([]byte, error) {
	s.Stack.push(new(Word).SetAddress(in.evm.TxContext.Origin))
	return nil, nil
}

func opCaller(_ *uint64, _ *Interpreter, s *ScopeContext) ([]byte, error) {
	s.Stack.push(new(Word).SetAddress(s.Contract.Caller()))
	return nil, nil
}

func opCallValue(_ *uint64, _ *Interpreter, s *ScopeContext) ([]byte, error) {
	s.Stack.push(s.Contract.Value())
	return nil, nil
}

// opCallDataLoad lee 32 bytes del calldata (rellenando con ceros).
func opCallDataLoad(_ *uint64, _ *Interpreter, s *ScopeContext) ([]byte, error) {
	x := s.Stack.peek()
	off, overflow := x.Uint64WithOverflow()
	if overflow || off >= uint64(len(s.Contract.Input)) {
		x.Clear()
		return nil, nil
	}
	var buf [32]byte
	copy(buf[:], s.Contract.Input[off:])
	x.SetBytes(buf[:])
	return nil, nil
}

func opCallDataSize(_ *uint64, _ *Interpreter, s *ScopeContext) ([]byte, error) {
	s.Stack.push(NewWord(uint64(len(s.Contract.Input))))
	return nil, nil
}

func opCallDataCopy(_ *uint64, _ *Interpreter, s *ScopeContext) ([]byte, error) {
	memOff, dataOff, length := s.Stack.pop(), s.Stack.pop(), s.Stack.pop()
	s.Memory.setPadded(memOff.Uint64(), s.Contract.Input, &dataOff, length.Uint64())
	return nil, nil
}

func opCodeSize(_ *uint64, _ *Interpreter, s *ScopeContext) ([]byte, error) {
	s.Stack.push(NewWord(uint64(len(s.Contract.Code))))
	return nil, nil
}

func opCodeCopy(_ *uint64, _ *Interpreter, s *ScopeContext) ([]byte, error) {
	memOff, codeOff, length := s.Stack.pop(), s.Stack.pop(), s.Stack.pop()
	s.Memory.setPadded(memOff.Uint64(), s.Contract.Code, &codeOff, length.Uint64())
	return nil, nil
}

func opGasprice(_ *uint64, in *Interpreter, s *ScopeContext) ([]byte, error) {
	s.Stack.push(WordFromAmount(in.evm.TxContext.GasPrice))
	return nil, nil
}

func opExtCodeSize(_ *uint64, in *Interpreter, s *ScopeContext) ([]byte, error) {
	slot := s.Stack.peek()
	slot.SetUint64(uint64(in.evm.StateDB.GetCodeSize(slot.Address())))
	return nil, nil
}

func opExtCodeCopy(_ *uint64, in *Interpreter, s *ScopeContext) ([]byte, error) {
	a, memOff, codeOff, length := s.Stack.pop(), s.Stack.pop(), s.Stack.pop(), s.Stack.pop()
	code := in.evm.StateDB.GetCode(a.Address())
	s.Memory.setPadded(memOff.Uint64(), code, &codeOff, length.Uint64())
	return nil, nil
}

func opReturnDataSize(_ *uint64, in *Interpreter, s *ScopeContext) ([]byte, error) {
	s.Stack.push(NewWord(uint64(len(in.returnData))))
	return nil, nil
}

// opReturnDataCopy: a diferencia de CALLDATACOPY, leer fuera de los datos
// de retorno es un error que consume todo el gas (EIP-211).
func opReturnDataCopy(_ *uint64, in *Interpreter, s *ScopeContext) ([]byte, error) {
	memOff, dataOff, length := s.Stack.pop(), s.Stack.pop(), s.Stack.pop()
	off, overflow := dataOff.Uint64WithOverflow()
	if overflow {
		return nil, ErrReturnDataOutOfBounds
	}
	end, overflow := safeAdd(off, length.Uint64())
	if overflow || !length.IsUint64() || uint64(len(in.returnData)) < end {
		return nil, ErrReturnDataOutOfBounds
	}
	s.Memory.Set(memOff.Uint64(), length.Uint64(), in.returnData[off:end])
	return nil, nil
}

// opExtCodeHash devuelve 0 para cuentas inexistentes o vacías (EIP-1052 +
// EIP-161) y el hash del código en otro caso (Keccak("") para EOAs).
func opExtCodeHash(_ *uint64, in *Interpreter, s *ScopeContext) ([]byte, error) {
	slot := s.Stack.peek()
	addr := slot.Address()
	if in.evm.StateDB.Empty(addr) {
		slot.Clear()
	} else {
		slot.SetHash(in.evm.StateDB.GetCodeHash(addr))
	}
	return nil, nil
}

// opBlockhash sólo resuelve los 256 bloques anteriores al actual.
func opBlockhash(_ *uint64, in *Interpreter, s *ScopeContext) ([]byte, error) {
	num := s.Stack.peek()
	n, overflow := num.Uint64WithOverflow()
	if overflow {
		num.Clear()
		return nil, nil
	}
	cur := in.evm.Context.BlockNumber
	var lower uint64
	if cur > 256 {
		lower = cur - 256
	}
	if n >= lower && n < cur {
		num.SetHash(in.evm.Context.GetHash(n))
	} else {
		num.Clear()
	}
	return nil, nil
}

func opCoinbase(_ *uint64, in *Interpreter, s *ScopeContext) ([]byte, error) {
	s.Stack.push(new(Word).SetAddress(in.evm.Context.Coinbase))
	return nil, nil
}

func opTimestamp(_ *uint64, in *Interpreter, s *ScopeContext) ([]byte, error) {
	s.Stack.push(NewWord(in.evm.Context.Time))
	return nil, nil
}

func opNumber(_ *uint64, in *Interpreter, s *ScopeContext) ([]byte, error) {
	s.Stack.push(NewWord(in.evm.Context.BlockNumber))
	return nil, nil
}

// opRandom expone la aleatoriedad del consenso (salida VRF del proponente).
func opRandom(_ *uint64, in *Interpreter, s *ScopeContext) ([]byte, error) {
	s.Stack.push(new(Word).SetHash(in.evm.Context.Random))
	return nil, nil
}

func opGasLimit(_ *uint64, in *Interpreter, s *ScopeContext) ([]byte, error) {
	s.Stack.push(NewWord(in.evm.Context.GasLimit))
	return nil, nil
}

func opChainID(_ *uint64, in *Interpreter, s *ScopeContext) ([]byte, error) {
	s.Stack.push(NewWord(in.evm.ChainConfig.ChainID.Uint64()))
	return nil, nil
}

func opSelfBalance(_ *uint64, in *Interpreter, s *ScopeContext) ([]byte, error) {
	s.Stack.push(WordFromAmount(in.evm.StateDB.GetBalance(s.Contract.Address())))
	return nil, nil
}

func opBaseFee(_ *uint64, in *Interpreter, s *ScopeContext) ([]byte, error) {
	s.Stack.push(WordFromAmount(in.evm.Context.BaseFee))
	return nil, nil
}

// opBlobHash: la cadena no admite transacciones con blobs, así que no hay
// hashes versionados y el resultado es siempre 0.
func opBlobHash(_ *uint64, _ *Interpreter, s *ScopeContext) ([]byte, error) {
	s.Stack.peek().Clear()
	return nil, nil
}

// opBlobBaseFee devuelve el mínimo de EIP-4844 (1 wei), constante.
func opBlobBaseFee(_ *uint64, _ *Interpreter, s *ScopeContext) ([]byte, error) {
	s.Stack.push(NewWord(1))
	return nil, nil
}
