package execution

// Este archivo implementa las cuatro variantes de llamada entre contratos
// (CALL, CALLCODE, DELEGATECALL, STATICCALL), tanto como métodos de EVM
// (usados por la transición de estado y por las propias instrucciones)
// como las instrucciones del intérprete, además de SELFDESTRUCT.
//
// Invariante común: cada llamada toma una instantánea del estado; si la
// llamada falla se revierte y, salvo que el fallo sea un REVERT explícito,
// se consume todo el gas entregado.

import "github.com/l1/l1/types"

// Call ejecuta el código de addr con la entrada dada, transfiriendo value
// desde caller. Si addr no existe y no se envía valor, no se crea la cuenta
// (EIP-161) y la llamada tiene éxito sin ejecutar nada.
func (evm *EVM) Call(caller, addr types.Address, input []byte, gas uint64, value *Word) (ret []byte, leftOverGas uint64, err error) {
	if value == nil {
		value = new(Word)
	}
	evm.tracerEnter(CALL, caller, addr, input, gas, value)
	defer func(startGas uint64) { evm.tracerExit(ret, startGas, leftOverGas, err) }(gas)

	if evm.depth > int(CallCreateDepth) {
		return nil, gas, ErrDepth
	}
	if !value.IsZero() && !evm.Context.CanTransfer(evm.StateDB, caller, value) {
		return nil, gas, ErrInsufficientBalance
	}
	snapshot := evm.StateDB.Snapshot()
	p, isPrecompile := evm.precompile(addr)
	sys, isSystem := evm.systemContract(addr)

	if !evm.StateDB.Exist(addr) {
		if !isPrecompile && !isSystem && value.IsZero() {
			return nil, gas, nil
		}
		evm.StateDB.CreateAccount(addr)
	}
	if err = evm.Context.Transfer(evm.StateDB, caller, addr, value); err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		return nil, gas, err
	}

	switch {
	case isPrecompile:
		ret, gas, err = RunPrecompiledContract(p, input, gas)
	case isSystem:
		ret, gas, err = runSystemContract(evm, sys, caller, input, gas, value, evm.interpreter.readOnly)
	default:
		code := evm.StateDB.GetCode(addr)
		if len(code) == 0 {
			ret, err = nil, nil // transferencia simple a una EOA
		} else {
			addrCopy := addr
			contract := NewContract(caller, addrCopy, value, gas)
			contract.SetCallCode(&addrCopy, evm.StateDB.GetCodeHash(addrCopy), code)
			ret, err = evm.interpreter.Run(contract, input, false)
			gas = contract.Gas
		}
	}
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != ErrExecutionReverted {
			gas = 0
		}
	}
	return ret, gas, err
}

// CallCode ejecuta el código de addr en el contexto (almacenamiento y
// saldo) de caller. Variante histórica; DELEGATECALL la sustituye.
func (evm *EVM) CallCode(caller, addr types.Address, input []byte, gas uint64, value *Word) (ret []byte, leftOverGas uint64, err error) {
	if value == nil {
		value = new(Word)
	}
	evm.tracerEnter(CALLCODE, caller, addr, input, gas, value)
	defer func(startGas uint64) { evm.tracerExit(ret, startGas, leftOverGas, err) }(gas)

	if evm.depth > int(CallCreateDepth) {
		return nil, gas, ErrDepth
	}
	// Aunque el valor se "envía" a uno mismo, debe haber saldo suficiente.
	if !value.IsZero() && !evm.Context.CanTransfer(evm.StateDB, caller, value) {
		return nil, gas, ErrInsufficientBalance
	}
	snapshot := evm.StateDB.Snapshot()
	if p, ok := evm.precompile(addr); ok {
		ret, gas, err = RunPrecompiledContract(p, input, gas)
	} else {
		addrCopy := addr
		contract := NewContract(caller, caller, value, gas)
		contract.SetCallCode(&addrCopy, evm.StateDB.GetCodeHash(addrCopy), evm.StateDB.GetCode(addrCopy))
		ret, err = evm.interpreter.Run(contract, input, false)
		gas = contract.Gas
	}
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != ErrExecutionReverted {
			gas = 0
		}
	}
	return ret, gas, err
}

// DelegateCall ejecuta el código de addr en el contexto de caller
// conservando el msg.sender (originCaller) y msg.value del marco padre.
// Es la base de los proxies y librerías.
func (evm *EVM) DelegateCall(originCaller, caller, addr types.Address, input []byte, gas uint64, value *Word) (ret []byte, leftOverGas uint64, err error) {
	if value == nil {
		value = new(Word)
	}
	evm.tracerEnter(DELEGATECALL, caller, addr, input, gas, nil)
	defer func(startGas uint64) { evm.tracerExit(ret, startGas, leftOverGas, err) }(gas)

	if evm.depth > int(CallCreateDepth) {
		return nil, gas, ErrDepth
	}
	snapshot := evm.StateDB.Snapshot()
	if p, ok := evm.precompile(addr); ok {
		ret, gas, err = RunPrecompiledContract(p, input, gas)
	} else {
		addrCopy := addr
		contract := NewContract(originCaller, caller, value, gas)
		contract.SetCallCode(&addrCopy, evm.StateDB.GetCodeHash(addrCopy), evm.StateDB.GetCode(addrCopy))
		ret, err = evm.interpreter.Run(contract, input, false)
		gas = contract.Gas
	}
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != ErrExecutionReverted {
			gas = 0
		}
	}
	return ret, gas, err
}

// StaticCall ejecuta addr prohibiendo cualquier modificación de estado
// (EIP-214): SSTORE, LOG, CREATE, SELFDESTRUCT o CALL con valor fallan.
func (evm *EVM) StaticCall(caller, addr types.Address, input []byte, gas uint64) (ret []byte, leftOverGas uint64, err error) {
	evm.tracerEnter(STATICCALL, caller, addr, input, gas, nil)
	defer func(startGas uint64) { evm.tracerExit(ret, startGas, leftOverGas, err) }(gas)

	if evm.depth > int(CallCreateDepth) {
		return nil, gas, ErrDepth
	}
	snapshot := evm.StateDB.Snapshot()
	// Sumar cero "toca" la cuenta, igual que en geth, para que la limpieza
	// de cuentas vacías (EIP-161) se comporte de forma idéntica.
	evm.StateDB.AddBalance(addr, types.Amount{})

	if p, ok := evm.precompile(addr); ok {
		ret, gas, err = RunPrecompiledContract(p, input, gas)
	} else if sys, ok := evm.systemContract(addr); ok {
		ret, gas, err = runSystemContract(evm, sys, caller, input, gas, new(Word), true)
	} else {
		addrCopy := addr
		contract := NewContract(caller, addrCopy, new(Word), gas)
		contract.SetCallCode(&addrCopy, evm.StateDB.GetCodeHash(addrCopy), evm.StateDB.GetCode(addrCopy))
		ret, err = evm.interpreter.Run(contract, input, true)
		gas = contract.Gas
	}
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != ErrExecutionReverted {
			gas = 0
		}
	}
	return ret, gas, err
}

// ---------------------------------------------------------------------------
// Instrucciones
// ---------------------------------------------------------------------------

// finishCall deja en la pila el resultado (1 éxito, 0 fallo), copia la
// salida a memoria si procede, devuelve el gas sobrante y actualiza los
// datos de retorno.
func finishCall(in *Interpreter, s *ScopeContext, ret []byte, returnGas uint64, err error, retOff, retSize uint64) ([]byte, error) {
	var res Word
	if err == nil {
		res.SetOne()
	}
	s.Stack.push(&res)
	if err == nil || err == ErrExecutionReverted {
		s.Memory.Set(retOff, retSize, ret)
	}
	s.Contract.RefundGas(returnGas)
	in.returnData = ret
	return ret, nil
}

// opCall: gas, addr, value, argsOff, argsLen, retOff, retLen.
func opCall(_ *uint64, in *Interpreter, s *ScopeContext) ([]byte, error) {
	st := s.Stack
	st.pop() // el gas pedido ya se procesó en gasCall (callGasTemp)
	gas := in.evm.callGasTemp
	addr, value := st.pop(), st.pop()
	inOff, inSize, retOff, retSize := st.pop(), st.pop(), st.pop(), st.pop()
	if in.readOnly && !value.IsZero() {
		return nil, ErrWriteProtection
	}
	if !value.IsZero() {
		gas += CallStipend // estipendio gratuito para que el receptor emita logs
	}
	args := s.Memory.GetCopy(inOff.Uint64(), inSize.Uint64())
	ret, returnGas, err := in.evm.Call(s.Contract.Address(), addr.Address(), args, gas, &value)
	return finishCall(in, s, ret, returnGas, err, retOff.Uint64(), retSize.Uint64())
}

// opCallCode: mismos operandos que CALL.
func opCallCode(_ *uint64, in *Interpreter, s *ScopeContext) ([]byte, error) {
	st := s.Stack
	st.pop()
	gas := in.evm.callGasTemp
	addr, value := st.pop(), st.pop()
	inOff, inSize, retOff, retSize := st.pop(), st.pop(), st.pop(), st.pop()
	if !value.IsZero() {
		gas += CallStipend
	}
	args := s.Memory.GetCopy(inOff.Uint64(), inSize.Uint64())
	ret, returnGas, err := in.evm.CallCode(s.Contract.Address(), addr.Address(), args, gas, &value)
	return finishCall(in, s, ret, returnGas, err, retOff.Uint64(), retSize.Uint64())
}

// opDelegateCall: gas, addr, argsOff, argsLen, retOff, retLen.
func opDelegateCall(_ *uint64, in *Interpreter, s *ScopeContext) ([]byte, error) {
	st := s.Stack
	st.pop()
	gas := in.evm.callGasTemp
	addr := st.pop()
	inOff, inSize, retOff, retSize := st.pop(), st.pop(), st.pop(), st.pop()
	args := s.Memory.GetCopy(inOff.Uint64(), inSize.Uint64())
	ret, returnGas, err := in.evm.DelegateCall(s.Contract.Caller(), s.Contract.Address(), addr.Address(), args, gas, s.Contract.Value())
	return finishCall(in, s, ret, returnGas, err, retOff.Uint64(), retSize.Uint64())
}

// opStaticCall: gas, addr, argsOff, argsLen, retOff, retLen.
func opStaticCall(_ *uint64, in *Interpreter, s *ScopeContext) ([]byte, error) {
	st := s.Stack
	st.pop()
	gas := in.evm.callGasTemp
	addr := st.pop()
	inOff, inSize, retOff, retSize := st.pop(), st.pop(), st.pop(), st.pop()
	args := s.Memory.GetCopy(inOff.Uint64(), inSize.Uint64())
	ret, returnGas, err := in.evm.StaticCall(s.Contract.Address(), addr.Address(), args, gas)
	return finishCall(in, s, ret, returnGas, err, retOff.Uint64(), retSize.Uint64())
}

// opSelfdestruct implementa EIP-6780: el saldo siempre pasa al
// beneficiario, pero la cuenta sólo se elimina si se creó en la misma
// transacción.
func opSelfdestruct(_ *uint64, in *Interpreter, s *ScopeContext) ([]byte, error) {
	if in.readOnly {
		return nil, ErrWriteProtection
	}
	beneficiary := s.Stack.pop()
	self := s.Contract.Address()
	db := in.evm.StateDB
	balance := db.GetBalance(self)
	if err := db.SubBalance(self, balance); err != nil {
		return nil, err
	}
	db.AddBalance(beneficiary.Address(), balance)
	db.SelfDestruct6780(self)
	if h := in.evm.Config.Tracer; h != nil && h.OnEnter != nil {
		// Se notifica como un marco instantáneo, igual que geth.
		h.OnEnter(in.evm.depth, SELFDESTRUCT, self, beneficiary.Address(), nil, 0, WordFromAmount(balance))
		if h.OnExit != nil {
			h.OnExit(in.evm.depth, nil, 0, nil, false)
		}
	}
	return nil, errStopToken
}
