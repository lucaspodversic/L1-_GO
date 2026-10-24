package storage

// Almacén de recibos. Se guardan por bloque como una lista RLP de recibos en
// formato de almacenamiento (Receipt.EncodeStorage); los campos derivados
// (hash/número de bloque, índices de log, etc.) se recalculan al leer con
// Receipts.DeriveFields, por lo que no ocupan disco.

import (
	"errors"

	"github.com/l1/l1/types"
)

// WriteReceipts guarda los recibos de un bloque.
func WriteReceipts(w KeyValueWriter, hash types.Hash, n uint64, rs types.Receipts) error {
	items := make([][]byte, len(rs))
	for i, r := range rs {
		items[i] = r.EncodeStorage()
	}
	return w.Put(receiptsKey(n, hash), types.EncodeList(items...))
}

// ReadRawReceipts lee los recibos sin campos derivados.
func ReadRawReceipts(r KeyValueReader, hash types.Hash, n uint64) (types.Receipts, error) {
	v, err := r.Get(receiptsKey(n, hash))
	if errors.Is(err, ErrNotFound) {
		return nil, ErrBlockNotFound
	}
	if err != nil {
		return nil, err
	}
	it, err := types.DecodeRLP(v)
	if err != nil {
		return nil, err
	}
	list, err := it.Items()
	if err != nil {
		return nil, err
	}
	out := make(types.Receipts, len(list))
	for i, item := range list {
		if out[i], err = types.DecodeStorageReceipt(item); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// ReadReceipts lee los recibos y completa sus campos derivados con las
// transacciones del bloque.
func ReadReceipts(r KeyValueReader, hash types.Hash, n uint64, txs types.Transactions) (types.Receipts, error) {
	rs, err := ReadRawReceipts(r, hash, n)
	if err != nil {
		return nil, err
	}
	if err := rs.DeriveFields(hash, n, txs); err != nil {
		return nil, err
	}
	return rs, nil
}

// DeleteReceipts borra los recibos del bloque.
func DeleteReceipts(w KeyValueWriter, hash types.Hash, n uint64) error {
	return w.Delete(receiptsKey(n, hash))
}

// HasReceipts informa si hay recibos guardados para el bloque.
func HasReceipts(r KeyValueReader, hash types.Hash, n uint64) bool {
	ok, _ := r.Has(receiptsKey(n, hash))
	return ok
}

// ReadReceipt devuelve el recibo de una transacción canónica por su hash.
func ReadReceipt(r KeyValueReader, txHash types.Hash) (*types.Receipt, error) {
	e, err := ReadTxLookupEntry(r, txHash)
	if err != nil {
		return nil, err
	}
	body, err := ReadBody(r, e.BlockHash, e.BlockNumber)
	if err != nil {
		return nil, err
	}
	rs, err := ReadReceipts(r, e.BlockHash, e.BlockNumber, body.Transactions)
	if err != nil {
		return nil, err
	}
	if e.Index >= uint64(len(rs)) || rs[e.Index].TxHash != txHash {
		return nil, ErrTxNotFound
	}
	return rs[e.Index], nil
}
