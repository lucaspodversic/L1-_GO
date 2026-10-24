package execution

// Este archivo implementa las instrucciones de almacenamiento:
//
//   - SLOAD/SSTORE: almacenamiento persistente del contrato, con el gas de
//     EIP-2929 (accesos fríos/tibios), EIP-2200 (medición neta) y los
//     reembolsos reducidos de EIP-3529.
//   - TLOAD/TSTORE: almacenamiento transitorio (EIP-1153), que se borra al
//     final de cada transacción y cuesta siempre 100 gas.

// gasSLoad: 2100 si la ranura está fría (y la calienta), 100 si está tibia.
func gasSLoad(evm *EVM, contract *Contract, stack *Stack, _ *Memory, _ uint64) (uint64, error) {
	loc := stack.Back(0).Hash()
	if _, slotOk := evm.StateDB.SlotInAccessList(contract.Address(), loc); !slotOk {
		evm.StateDB.AddSlotToAccessList(contract.Address(), loc)
		return ColdSloadCost, nil
	}
	return WarmStorageReadCost, nil
}

// gasSStore implementa la medición neta de SSTORE. Distingue tres valores:
// original (al inicio de la tx), current (actual) y value (nuevo):
//
//   - Sin cambio (current == value): 100.
//   - Primera modificación en la tx (original == current):
//     0 -> x cuesta 20000; x -> y cuesta 2900 (+4800 de reembolso si y = 0).
//   - Ranura ya modificada ("sucia"): 100, ajustando reembolsos para que
//     restaurar el valor original devuelva lo pagado de más.
//
// Además, se exige que queden más de 2300 gas (EIP-2200) para que un
// receptor con el estipendio de CALL no pueda modificar almacenamiento.
func gasSStore(evm *EVM, contract *Contract, stack *Stack, _ *Memory, _ uint64) (uint64, error) {
	if contract.Gas <= SstoreSentryGas {
		return 0, ErrOutOfGas
	}
	var cost uint64
	addr := contract.Address()
	slot := stack.Back(0).Hash()
	if _, slotOk := evm.StateDB.SlotInAccessList(addr, slot); !slotOk {
		cost = ColdSloadCost
		evm.StateDB.AddSlotToAccessList(addr, slot)
	}
	value := stack.Back(1).Hash()
	current := evm.StateDB.GetState(addr, slot)
	if current == value { // no-op
		return cost + WarmStorageReadCost, nil
	}
	original := evm.StateDB.GetCommittedState(addr, slot)
	if original == current {
		if original.IsZero() { // creación de ranura
			return cost + SstoreSetGas, nil
		}
		if value.IsZero() { // borrado de ranura
			evm.StateDB.AddRefund(SstoreClearsScheduleRefund)
		}
		return cost + (SstoreResetGas - ColdSloadCost), nil // escritura
	}
	// Ranura sucia.
	if !original.IsZero() {
		if current.IsZero() { // se recrea una ranura borrada antes
			evm.StateDB.SubRefund(SstoreClearsScheduleRefund)
		} else if value.IsZero() { // se borra ahora
			evm.StateDB.AddRefund(SstoreClearsScheduleRefund)
		}
	}
	if original == value { // se restaura el valor original
		if original.IsZero() {
			evm.StateDB.AddRefund(SstoreSetGas - WarmStorageReadCost)
		} else {
			evm.StateDB.AddRefund((SstoreResetGas - ColdSloadCost) - WarmStorageReadCost)
		}
	}
	return cost + WarmStorageReadCost, nil
}

// opSload lee una ranura persistente.
func opSload(_ *uint64, in *Interpreter, s *ScopeContext) ([]byte, error) {
	loc := s.Stack.peek()
	val := in.evm.StateDB.GetState(s.Contract.Address(), loc.Hash())
	loc.SetHash(val)
	return nil, nil
}

// opSstore escribe una ranura persistente (prohibido en STATICCALL).
func opSstore(_ *uint64, in *Interpreter, s *ScopeContext) ([]byte, error) {
	if in.readOnly {
		return nil, ErrWriteProtection
	}
	loc, val := s.Stack.pop(), s.Stack.pop()
	in.evm.StateDB.SetState(s.Contract.Address(), loc.Hash(), val.Hash())
	return nil, nil
}

// opTload lee una ranura transitoria.
func opTload(_ *uint64, in *Interpreter, s *ScopeContext) ([]byte, error) {
	loc := s.Stack.peek()
	val := in.evm.StateDB.GetTransientState(s.Contract.Address(), loc.Hash())
	loc.SetHash(val)
	return nil, nil
}

// opTstore escribe una ranura transitoria (también prohibido en estático,
// según EIP-1153).
func opTstore(_ *uint64, in *Interpreter, s *ScopeContext) ([]byte, error) {
	if in.readOnly {
		return nil, ErrWriteProtection
	}
	loc, val := s.Stack.pop(), s.Stack.pop()
	in.evm.StateDB.SetTransientState(s.Contract.Address(), loc.Hash(), val.Hash())
	return nil, nil
}
