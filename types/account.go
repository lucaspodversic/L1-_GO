package types

// Este archivo define Account, el estado persistido de cada dirección en el
// trie de estado. El formato RLP [nonce, balance, storageRoot, codeHash] es el
// de Ethereum, de modo que las pruebas de Merkle (eth_getProof) son
// verificables con herramientas existentes.

// Account es el estado de consenso de una cuenta.
type Account struct {
	// Nonce cuenta las transacciones enviadas (o contratos creados, si es contrato).
	Nonce uint64 `json:"nonce"`
	// Balance es el saldo en wei.
	Balance Amount `json:"balance"`
	// StorageRoot es la raíz del trie de almacenamiento del contrato
	// (EmptyRootHash si no tiene almacenamiento).
	StorageRoot Hash `json:"storageRoot"`
	// CodeHash es Keccak256 del código (EmptyCodeHash si no es contrato).
	CodeHash Hash `json:"codeHash"`
}

// NewEmptyAccount devuelve una cuenta vacía con las raíces por defecto
// correctas. OJO: Account{} (todo ceros) NO es una cuenta vacía válida porque
// sus hashes serían cero y no EmptyRootHash / EmptyCodeHash.
func NewEmptyAccount() Account {
	return Account{StorageRoot: EmptyRootHash, CodeHash: EmptyCodeHash}
}

// IsEmpty implementa la definición de EIP-161: nonce 0, balance 0 y sin
// código. Las cuentas vacías "tocadas" se borran del estado al final de cada
// transacción para no inflarlo.
func (a *Account) IsEmpty() bool {
	return a.Nonce == 0 && a.Balance.IsZero() && a.CodeHash == EmptyCodeHash
}

// HasCode informa si la cuenta es un contrato.
func (a *Account) HasCode() bool { return a.CodeHash != EmptyCodeHash && !a.CodeHash.IsZero() }

// Copy devuelve una copia (Amount es inmutable, así que basta copiar el struct).
func (a *Account) Copy() *Account {
	c := *a
	return &c
}

// EncodeRLP codifica la cuenta para el trie de estado.
func (a *Account) EncodeRLP() []byte {
	return EncodeList(EncodeUint(a.Nonce), a.Balance.EncodeRLP(), a.StorageRoot.EncodeRLP(), a.CodeHash.EncodeRLP())
}

// DecodeAccount decodifica una cuenta desde su RLP.
func DecodeAccount(b []byte) (*Account, error) {
	it, err := DecodeRLP(b)
	if err != nil {
		return nil, err
	}
	f, err := it.ListN(4)
	if err != nil {
		return nil, err
	}
	a := &Account{}
	if a.Nonce, err = f[0].Uint64(); err != nil {
		return nil, err
	}
	if a.Balance, err = DecodeAmountRLP(f[1]); err != nil {
		return nil, err
	}
	if a.StorageRoot, err = f[2].Hash(); err != nil {
		return nil, err
	}
	if a.CodeHash, err = f[3].Hash(); err != nil {
		return nil, err
	}
	return a, nil
}
