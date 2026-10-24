package storage

// Índice de transacciones: txHash → (bloque, posición). Permite responder
// eth_getTransactionByHash / eth_getTransactionReceipt sin recorrer bloques.
// Sólo se indexan transacciones de bloques canónicos; al reorganizar se
// borran o se sobrescriben.

import (
	"errors"

	"github.com/l1/l1/types"
)

// TxLookupEntry ubica una transacción en la cadena.
type TxLookupEntry struct {
	// BlockHash es el bloque que la contiene.
	BlockHash types.Hash
	// BlockNumber es su altura.
	BlockNumber uint64
	// Index es la posición dentro del bloque.
	Index uint64
}

// ErrTxNotFound indica que la transacción no está indexada.
var ErrTxNotFound = errors.New("storage: transacción no encontrada")

// txLookupKey = l + txHash.
func txLookupKey(h types.Hash) []byte { return concat(txLookupPrefix, h[:]) }

// encode codifica la entrada como RLP [hash, num, idx].
func (e *TxLookupEntry) encode() []byte {
	return types.EncodeList(e.BlockHash.EncodeRLP(), types.EncodeUint(e.BlockNumber), types.EncodeUint(e.Index))
}

// decodeTxLookup decodifica una entrada.
func decodeTxLookup(b []byte) (*TxLookupEntry, error) {
	it, err := types.DecodeRLP(b)
	if err != nil {
		return nil, err
	}
	f, err := it.ListN(3)
	if err != nil {
		return nil, err
	}
	e := &TxLookupEntry{}
	if e.BlockHash, err = f[0].Hash(); err != nil {
		return nil, err
	}
	if e.BlockNumber, err = f[1].Uint64(); err != nil {
		return nil, err
	}
	if e.Index, err = f[2].Uint64(); err != nil {
		return nil, err
	}
	return e, nil
}

// WriteTxLookupEntries indexa todas las transacciones del bloque.
func WriteTxLookupEntries(w KeyValueWriter, b *types.Block) error {
	for i, tx := range b.Transactions() {
		e := TxLookupEntry{BlockHash: b.Hash(), BlockNumber: b.Number(), Index: uint64(i)}
		if err := w.Put(txLookupKey(tx.Hash()), e.encode()); err != nil {
			return err
		}
	}
	return nil
}

// ReadTxLookupEntry devuelve la ubicación de la transacción.
func ReadTxLookupEntry(r KeyValueReader, txHash types.Hash) (*TxLookupEntry, error) {
	v, err := r.Get(txLookupKey(txHash))
	if errors.Is(err, ErrNotFound) {
		return nil, ErrTxNotFound
	}
	if err != nil {
		return nil, err
	}
	return decodeTxLookup(v)
}

// DeleteTxLookupEntry elimina la entrada del índice.
func DeleteTxLookupEntry(w KeyValueWriter, txHash types.Hash) error {
	return w.Delete(txLookupKey(txHash))
}

// ReadTransaction resuelve la transacción completa a partir del índice.
// Comprueba que el hash en esa posición coincide (defensa ante índices
// obsoletos tras una reorganización interrumpida).
func ReadTransaction(r KeyValueReader, txHash types.Hash) (*types.Transaction, *TxLookupEntry, error) {
	e, err := ReadTxLookupEntry(r, txHash)
	if err != nil {
		return nil, nil, err
	}
	body, err := ReadBody(r, e.BlockHash, e.BlockNumber)
	if err != nil {
		return nil, nil, err
	}
	if e.Index >= uint64(len(body.Transactions)) {
		return nil, nil, ErrTxNotFound
	}
	tx := body.Transactions[e.Index]
	if tx.Hash() != txHash {
		return nil, nil, ErrTxNotFound
	}
	return tx, e, nil
}
