package execution

// Este archivo implementa la creación de contratos (CREATE, CREATE2 y las
// transacciones sin destinatario): cálculo de la dirección, detección de
// colisiones, ejecución del initcode y depósito del código resultante con
// los límites de EIP-170 (tamaño), EIP-3541 (prefijo 0xEF prohibido) y
// EIP-3860 (tamaño del initcode).

import "github.com/l1/l1/types"

// maxInitCodeSize es el límite de EIP-3860 como uint64.
const maxInitCodeSize = uint64(types.MaxInitCodeSize)

// Create crea un contrato con dirección Keccak(RLP(caller, nonce)).
func (evm *EVM) Create(caller types.Address, code []byte, gas uint64, value *Word) (ret []byte, contractAddr types.Address, leftOverGas uint64, err error) {
	contractAddr = types.CreateAddress(caller, evm.StateDB.GetNonce(caller))
	return evm.create(caller, code, gas, value, contractAddr, CREATE)
}

// Create2 crea un contrato con dirección determinista
// Keccak(0xff ++ caller ++ salt ++ Keccak(initcode)) (EIP-1014).
func (evm *EVM) Create2(caller types.Address, code []byte, gas uint64, value *Word, salt *Word) (ret []byte, contractAddr types.Address, leftOverGas uint64, err error) {
	contractAddr = types.CreateAddress2(caller, salt.Hash(), types.Keccak256Hash(code))
	return evm.create(caller, code, gas, value, contractAddr, CREATE2)
}

// create es la lógica común de creación.
func (evm *EVM) create(caller types.Address, code []byte, gas uint64, value *Word, address types.Address, typ OpCode) (ret []byte, addr types.Address, leftOverGas uint64, err error) {
	if value == nil {
		value = new(Word)
	}
	evm.tracerEnter(typ, caller, address, code, gas, value)
	defer func(startGas uint64) { evm.tracerExit(ret, startGas, leftOverGas, err) }(gas)

	if evm.depth > int(CallCreateDepth) {
		return nil, types.Address{}, gas, ErrDepth
	}
	if !evm.Context.CanTransfer(evm.StateDB, caller, value) {
		return nil, types.Address{}, gas, ErrInsufficientBalance
	}
	nonce := evm.StateDB.GetNonce(caller)
	if nonce+1 < nonce {
		return nil, types.Address{}, gas, ErrNonceUintOverflow
	}
	// El nonce del creador se incrementa aunque la creación falle después.
	evm.StateDB.SetNonce(caller, nonce+1)
	// EIP-2929: la dirección creada queda tibia aunque la creación falle.
	evm.StateDB.AddAddressToAccessList(address)

	// Colisión: ya hay nonce, código o almacenamiento en la dirección.
	// Consume todo el gas, como en Ethereum.
	if evm.StateDB.GetNonce(address) != 0 ||
		!isEmptyCodeHash(evm.StateDB.GetCodeHash(address)) ||
		!isEmptyRoot(evm.StateDB.GetStorageRoot(address)) {
		return nil, types.Address{}, 0, ErrContractAddressCollision
	}

	snapshot := evm.StateDB.Snapshot()
	if !evm.StateDB.Exist(address) {
		evm.StateDB.CreateAccount(address)
	}
	evm.StateDB.CreateContract(address)
	evm.StateDB.SetNonce(address, 1) // EIP-161: los contratos nacen con nonce 1
	if err = evm.Context.Transfer(evm.StateDB, caller, address, value); err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		return nil, types.Address{}, gas, err
	}

	addrCopy := address
	contract := NewContract(caller, address, value, gas)
	contract.SetCallCode(&addrCopy, types.Hash{}, code)
	contract.IsDeployment = true

	ret, err = evm.initNewContract(contract, address)
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != ErrExecutionReverted {
			contract.UseGas(contract.Gas)
		}
	}
	return ret, address, contract.Gas, err
}

// initNewContract ejecuta el initcode y, si tiene éxito, deposita el
// código devuelto pagando 200 gas por byte.
func (evm *EVM) initNewContract(contract *Contract, address types.Address) ([]byte, error) {
	ret, err := evm.interpreter.Run(contract, nil, false)
	if err != nil {
		return ret, err
	}
	if len(ret) > types.MaxCodeSize {
		return ret, ErrMaxCodeSizeExceeded
	}
	if len(ret) >= 1 && ret[0] == 0xEF {
		return ret, ErrInvalidCode // reservado para EOF (EIP-3541)
	}
	if !contract.UseGas(uint64(len(ret)) * CreateDataGas) {
		return ret, ErrCodeStoreOutOfGas
	}
	evm.StateDB.SetCode(address, ret)
	return ret, nil
}

// isEmptyCodeHash: cuenta inexistente (hash cero) o sin código.
func isEmptyCodeHash(h types.Hash) bool { return h.IsZero() || h == types.EmptyCodeHash }

// isEmptyRoot: sin almacenamiento.
func isEmptyRoot(h types.Hash) bool { return h.IsZero() || h == types.EmptyRootHash }

// opCreate: value, offset, size -> dirección (0 si falla).
func opCreate(_ *uint64, in *Interpreter, s *ScopeContext) ([]byte, error) {
	if in.readOnly {
		return nil, ErrWriteProtection
	}
	value, offset := s.Stack.pop(), s.Stack.pop()
	size := s.Stack.peek()
	input := s.Memory.GetCopy(offset.Uint64(), size.Uint64())
	return doCreate(in, s, input, &value, nil, size)
}

// opCreate2: value, offset, size, salt -> dirección (0 si falla).
func opCreate2(_ *uint64, in *Interpreter, s *ScopeContext) ([]byte, error) {
	if in.readOnly {
		return nil, ErrWriteProtection
	}
	value, offset, size := s.Stack.pop(), s.Stack.pop(), s.Stack.pop()
	salt := s.Stack.peek()
	input := s.Memory.GetCopy(offset.Uint64(), size.Uint64())
	saltCopy := *salt
	return doCreate(in, s, input, &value, &saltCopy, salt)
}

// doCreate comparte la parte final de CREATE/CREATE2: entrega todo el gas
// menos 1/64 (EIP-150), escribe el resultado en la cima de la pila (slot) y
// gestiona los datos de retorno (sólo se conservan si hubo REVERT).
func doCreate(in *Interpreter, s *ScopeContext, input []byte, value, salt, slot *Word) ([]byte, error) {
	gas := s.Contract.Gas
	gas -= gas / 64
	s.Contract.UseGas(gas)

	var (
		res       []byte
		addr      types.Address
		returnGas uint64
		suberr    error
	)
	if salt == nil {
		res, addr, returnGas, suberr = in.evm.Create(s.Contract.Address(), input, gas, value)
	} else {
		res, addr, returnGas, suberr = in.evm.Create2(s.Contract.Address(), input, gas, value, salt)
	}
	if suberr != nil {
		slot.Clear()
	} else {
		slot.SetAddress(addr)
	}
	s.Contract.RefundGas(returnGas)
	if suberr == ErrExecutionReverted {
		in.returnData = res
		return res, nil
	}
	in.returnData = nil
	return nil, nil
}
