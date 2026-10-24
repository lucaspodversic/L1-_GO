package execution

// Este archivo implementa las transferencias nativas de valor (la moneda de
// la cadena) que usan CALL, CREATE y las transacciones, más un camino
// rápido para transferencias simples entre cuentas sin código que evita
// crear un marco de ejecución.

import (
	"github.com/l1/l1/types"
)

// CanTransfer comprueba que addr tenga al menos amount.
func CanTransfer(db StateDB, addr types.Address, amount *Word) bool {
	if amount.IsZero() {
		return true
	}
	return !db.GetBalance(addr).Lt(amount.ToAmount())
}

// Transfer mueve amount de sender a recipient. Con importe cero no hace
// nada salvo "tocar" las cuentas (necesario para EIP-161).
func Transfer(db StateDB, sender, recipient types.Address, amount *Word) error {
	a := amount.ToAmount()
	if err := db.SubBalance(sender, a); err != nil {
		return ErrInsufficientBalance
	}
	db.AddBalance(recipient, a)
	return nil
}

// TransferAmount es la versión con Amount, para código nativo.
func TransferAmount(db StateDB, sender, recipient types.Address, amount types.Amount) error {
	if err := db.SubBalance(sender, amount); err != nil {
		return ErrInsufficientBalance
	}
	db.AddBalance(recipient, amount)
	return nil
}

// IsSimpleTransfer informa si una transacción es una transferencia pura:
// con destinatario, sin datos y hacia una cuenta sin código, precompilado
// ni contrato de sistema. Estas transacciones cuestan exactamente 21000 de
// gas (más la lista de acceso) y no necesitan intérprete.
func IsSimpleTransfer(evm *EVM, tx *types.Transaction) bool {
	if tx.To == nil || len(tx.Data) != 0 {
		return false
	}
	to := *tx.To
	if _, ok := evm.precompile(to); ok {
		return false
	}
	if _, ok := evm.systemContract(to); ok {
		return false
	}
	return evm.StateDB.GetCodeSize(to) == 0
}

// nativeTransfer realiza el camino rápido dentro de la transición de
// estado: mueve el valor (si hay fondos) sin ejecutar código.
func nativeTransfer(evm *EVM, from, to types.Address, value *Word) error {
	if !value.IsZero() && !evm.Context.CanTransfer(evm.StateDB, from, value) {
		return ErrInsufficientBalance
	}
	evm.tracerEnter(CALL, from, to, nil, 0, value)
	snapshot := evm.StateDB.Snapshot()
	if !evm.StateDB.Exist(to) && value.IsZero() {
		evm.tracerExit(nil, 0, 0, nil)
		return nil // no se crean cuentas vacías (EIP-161)
	}
	err := evm.Context.Transfer(evm.StateDB, from, to, value)
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
	}
	evm.tracerExit(nil, 0, 0, err)
	return err
}
