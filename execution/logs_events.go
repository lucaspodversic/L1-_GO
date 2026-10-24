package execution

// Este archivo implementa LOG0..LOG4, las instrucciones que emiten eventos
// (logs). Cada log lleva la dirección emisora, hasta cuatro temas de 32
// bytes y datos arbitrarios; se acumulan en el StateDB (y se revierten con
// él) y acaban en el recibo y el bloom de la transacción. También incluye
// utilidades para construir y filtrar logs desde Go (eventos ABI).

import (
	"github.com/l1/l1/types"
)

// makeGasLog cobra 375 por log, 375 por tema, 8 por byte de datos y la
// expansión de memoria.
func makeGasLog(n uint64) gasFunc {
	return func(_ *EVM, _ *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
		requestedSize, overflow := stack.Back(1).Uint64WithOverflow()
		if overflow {
			return 0, ErrGasUintOverflow
		}
		gas, err := memoryGasCost(mem, memorySize)
		if err != nil {
			return 0, err
		}
		if gas, overflow = safeAdd(gas, n*LogTopicGas); overflow {
			return 0, ErrGasUintOverflow
		}
		dataGas, overflow := safeMul(requestedSize, LogDataGas)
		if overflow {
			return 0, ErrGasUintOverflow
		}
		if gas, overflow = safeAdd(gas, dataGas); overflow {
			return 0, ErrGasUintOverflow
		}
		return gas, nil
	}
}

// makeLog crea la instrucción LOGn.
func makeLog(n int) executionFunc {
	return func(_ *uint64, in *Interpreter, s *ScopeContext) ([]byte, error) {
		if in.readOnly {
			return nil, ErrWriteProtection
		}
		mStart, mSize := s.Stack.pop(), s.Stack.pop()
		topics := make([]types.Hash, n)
		for i := 0; i < n; i++ {
			t := s.Stack.pop()
			topics[i] = t.Hash()
		}
		data := s.Memory.GetCopy(mStart.Uint64(), mSize.Uint64())
		l := &types.Log{
			Address:     s.Contract.Address(),
			Topics:      topics,
			Data:        data,
			BlockNumber: in.evm.Context.BlockNumber,
		}
		in.evm.StateDB.AddLog(l)
		if h := in.evm.Config.Tracer; h != nil && h.OnLog != nil {
			h.OnLog(l)
		}
		return nil, nil
	}
}

// EventSignature calcula el tema 0 de un evento Solidity a partir de su
// firma canónica, p.ej. "Transfer(address,address,uint256)".
func EventSignature(sig string) types.Hash { return types.Keccak256Hash([]byte(sig)) }

// EmitLog permite a código nativo (contratos de sistema) emitir un log como
// si lo hiciera el bytecode.
func EmitLog(evm *EVM, addr types.Address, topics []types.Hash, data []byte) {
	l := &types.Log{
		Address:     addr,
		Topics:      append([]types.Hash(nil), topics...),
		Data:        append([]byte(nil), data...),
		BlockNumber: evm.Context.BlockNumber,
	}
	evm.StateDB.AddLog(l)
	if h := evm.Config.Tracer; h != nil && h.OnLog != nil {
		h.OnLog(l)
	}
}

// LogFilter selecciona logs por dirección y temas, con la semántica de
// eth_getLogs: Topics[i] vacío es comodín; si no, el tema i debe coincidir
// con alguno de la lista.
type LogFilter struct {
	Addresses []types.Address
	Topics    [][]types.Hash
}

// Match informa si el log cumple el filtro.
func (f *LogFilter) Match(l *types.Log) bool {
	if len(f.Addresses) > 0 {
		found := false
		for _, a := range f.Addresses {
			if a == l.Address {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if len(f.Topics) > len(l.Topics) {
		return false
	}
	for i, alts := range f.Topics {
		if len(alts) == 0 {
			continue
		}
		ok := false
		for _, t := range alts {
			if t == l.Topics[i] {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// FilterLogs devuelve los logs que cumplen el filtro.
func FilterLogs(logs []*types.Log, f *LogFilter) []*types.Log {
	var out []*types.Log
	for _, l := range logs {
		if f.Match(l) {
			out = append(out, l)
		}
	}
	return out
}
