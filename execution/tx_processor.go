package execution

// Este archivo aplica una transacción concreta dentro de un bloque y
// produce su recibo. También define el GasPool, el contador de gas
// disponible en el bloque que impide que la suma de los gasLimit de las
// transacciones incluidas supere el límite del bloque.

import (
	"fmt"
	"math"

	"github.com/l1/l1/crypto"
	"github.com/l1/l1/storage"
	"github.com/l1/l1/types"
)

// GasPool es el gas que queda disponible en el bloque.
type GasPool uint64

// NewGasPool crea un pool con el límite del bloque.
func NewGasPool(limit uint64) *GasPool { gp := GasPool(limit); return &gp }

// AddGas devuelve gas al pool.
func (gp *GasPool) AddGas(amount uint64) *GasPool {
	if uint64(*gp) > math.MaxUint64-amount {
		panic("gas pool desbordado")
	}
	*gp += GasPool(amount)
	return gp
}

// SubGas reserva gas; falla si no queda suficiente.
func (gp *GasPool) SubGas(amount uint64) error {
	if uint64(*gp) < amount {
		return ErrGasLimitReached
	}
	*gp -= GasPool(amount)
	return nil
}

// Gas devuelve el gas disponible.
func (gp *GasPool) Gas() uint64 { return uint64(*gp) }

// SetGas fija el gas disponible.
func (gp *GasPool) SetGas(gas uint64) { *gp = GasPool(gas) }

// String implementa fmt.Stringer.
func (gp *GasPool) String() string { return fmt.Sprintf("%d", *gp) }

// ApplyTransaction aplica tx sobre statedb y devuelve su recibo. usedGas
// acumula el gas del bloque. Un error aquí invalida la transacción (y por
// tanto el bloque si se estaba importando).
func ApplyTransaction(evm *EVM, gp *GasPool, statedb *storage.StateDB, header *types.Header, tx *types.Transaction, txIndex int, usedGas *uint64, signer crypto.TxSigner) (*types.Receipt, error) {
	msg, err := TransactionToMessage(tx, signer, header.BaseFee)
	if err != nil {
		return nil, fmt.Errorf("tx %d [%s]: %w", txIndex, tx.Hash(), err)
	}
	if h := evm.Config.Tracer; h != nil && h.OnTxStart != nil {
		h.OnTxStart(evm, tx, msg.From)
	}
	receipt, err := applyMessageForReceipt(evm, gp, statedb, header, tx, txIndex, msg, usedGas)
	if h := evm.Config.Tracer; h != nil && h.OnTxEnd != nil {
		h.OnTxEnd(receipt, err)
	}
	if err != nil {
		return nil, fmt.Errorf("tx %d [%s]: %w", txIndex, tx.Hash(), err)
	}
	return receipt, nil
}

// applyMessageForReceipt ejecuta el mensaje y construye el recibo.
func applyMessageForReceipt(evm *EVM, gp *GasPool, statedb *storage.StateDB, header *types.Header, tx *types.Transaction, txIndex int, msg *Message, usedGas *uint64) (*types.Receipt, error) {
	statedb.SetTxContext(tx.Hash(), txIndex)
	result, err := ApplyMessage(evm, msg, gp)
	if err != nil {
		return nil, err
	}
	// Consolidamos la tx: se borran cuentas vacías y se limpia el journal.
	statedb.Finalise(true)
	*usedGas += result.UsedGas
	return MakeReceipt(statedb, header, tx, msg, result, *usedGas), nil
}

// MakeReceipt construye el recibo a partir del resultado.
func MakeReceipt(statedb *storage.StateDB, header *types.Header, tx *types.Transaction, msg *Message, result *ExecutionResult, cumulative uint64) *types.Receipt {
	r := &types.Receipt{
		Type:              tx.Type,
		CumulativeGasUsed: cumulative,
		TxHash:            tx.Hash(),
		GasUsed:           result.UsedGas,
		EffectiveGasPrice: msg.GasPrice,
		BlockNumber:       header.Number,
		TxIndex:           uint(statedb.TxIndex()),
	}
	if result.Failed() {
		r.Status = types.ReceiptStatusFailed
	} else {
		r.Status = types.ReceiptStatusSuccessful
	}
	if tx.To == nil {
		r.ContractAddress = types.CreateAddress(msg.From, tx.Nonce)
	}
	r.Logs = statedb.GetLogs(tx.Hash(), header.Number, types.Hash{})
	if r.Logs == nil {
		r.Logs = []*types.Log{}
	}
	r.Bloom = types.LogsBloom(r.Logs)
	return r
}
