package node

// Ayuda a construir y firmar transacciones desde la CLI/RPC.

import (
	"github.com/l1/l1/crypto"
	"github.com/l1/l1/types"
)

// TxBuilder construye txs dinámicas.
type TxBuilder struct {
	chainID types.ChainID
	signer  crypto.TxSigner
}

// NewTxBuilder crea el builder.
func NewTxBuilder(chainID types.ChainID) *TxBuilder {
	return &TxBuilder{chainID: chainID, signer: crypto.NewTxSigner(chainID)}
}

// BuildDynamic crea una tx EIP-1559 sin firmar.
func (b *TxBuilder) BuildDynamic(nonce uint64, to *types.Address, value types.Amount, gas uint64, tip, fee types.Amount, data []byte) *types.Transaction {
	return types.NewDynamicFeeTx(b.chainID, nonce, to, value, gas, tip, fee, data, nil)
}

// Sign firma con una clave secp256k1.
func (b *TxBuilder) Sign(tx *types.Transaction, key *crypto.Secp256k1PrivateKey) (*types.Transaction, error) {
	return b.signer.SignTx(tx, key)
}

// Sender recupera el remitente.
func (b *TxBuilder) Sender(tx *types.Transaction) (types.Address, error) {
	return b.signer.Sender(tx)
}
