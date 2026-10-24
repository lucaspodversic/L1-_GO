package types

// Este archivo define Block (cabecera + cuerpo), Body y el mecanismo genérico
// para calcular raíces de Merkle de listas (transacciones, recibos) sin
// depender del paquete storage, donde vive el Merkle Patricia Trie.

import (
	"fmt"
	"sync/atomic"
)

// TrieHasher es la abstracción mínima de un trie que permite calcular la
// raíz de una lista. La implementa storage (un trie en memoria). Se define
// aquí para invertir la dependencia: types no importa storage.
type TrieHasher interface {
	// Reset vacía el trie para reutilizarlo.
	Reset()
	// Update inserta key -> value.
	Update(key, value []byte) error
	// Hash devuelve la raíz actual.
	Hash() Hash
}

// DerivableList es una lista cuyos elementos se pueden codificar por índice.
type DerivableList interface {
	// Len devuelve la cantidad de elementos.
	Len() int
	// EncodeIndex devuelve la codificación del elemento i.
	EncodeIndex(i int) []byte
}

// DeriveRoot calcula la raíz de un trie con claves RLP(i) y valores
// list.EncodeIndex(i), exactamente como Ethereum calcula TxRoot y ReceiptRoot.
// Con lista vacía devuelve EmptyRootHash.
func DeriveRoot(list DerivableList, hasher TrieHasher) (Hash, error) {
	hasher.Reset()
	for i := 0; i < list.Len(); i++ {
		if err := hasher.Update(EncodeUintKey(i), list.EncodeIndex(i)); err != nil {
			return Hash{}, err
		}
	}
	return hasher.Hash(), nil
}

// Body es la parte del bloque que no va en la cabecera.
type Body struct {
	// Transactions son las transacciones en orden de ejecución.
	Transactions Transactions
	// Justify es el QC (codificado por el paquete consensus) que certifica al
	// bloque padre. Su hash debe coincidir con Header.JustifyHash.
	Justify []byte
}

// EncodeRLP codifica el cuerpo como [[tx...], justify], donde cada tx va como
// string con su codificación binaria (uniforme para legacy y tipadas).
func (b *Body) EncodeRLP() []byte {
	txs, justify := b.encodeParts()
	return EncodeList(txs, justify)
}

// encodeParts devuelve por separado la lista de txs y el justify ya
// codificados, para reutilizarlos en la codificación plana del bloque.
func (b *Body) encodeParts() (txList, justify []byte) {
	txs := make([][]byte, len(b.Transactions))
	for i, tx := range b.Transactions {
		txs[i] = EncodeBytes(tx.MustMarshalBinary())
	}
	return EncodeList(txs...), EncodeBytes(b.Justify)
}

// DecodeBody decodifica un cuerpo desde RLP.
func DecodeBody(data []byte) (*Body, error) {
	it, err := DecodeRLP(data)
	if err != nil {
		return nil, err
	}
	return decodeBodyItems(it)
}

// decodeBodyItems decodifica un cuerpo desde un ítem ya parseado.
func decodeBodyItems(it RLPItem) (*Body, error) {
	f, err := it.ListN(2)
	if err != nil {
		return nil, err
	}
	txItems, err := f[0].Items()
	if err != nil {
		return nil, err
	}
	body := &Body{Transactions: make(Transactions, 0, len(txItems))}
	for i, ti := range txItems {
		raw, err := ti.Bytes()
		if err != nil {
			return nil, err
		}
		tx, err := DecodeTransaction(raw)
		if err != nil {
			return nil, fmt.Errorf("tx %d: %w", i, err)
		}
		body.Transactions = append(body.Transactions, tx)
	}
	if body.Justify, err = f[1].BytesCopy(); err != nil {
		return nil, err
	}
	return body, nil
}

// Block es un bloque completo. Como Header y Transaction, se trata como
// inmutable una vez construido.
type Block struct {
	// header es la cabecera (privada para impedir modificarla sin Copy).
	header *Header
	// transactions son las transacciones del bloque.
	transactions Transactions
	// justify es el QC del padre en bytes opacos.
	justify []byte

	// size cachea el tamaño codificado.
	size atomic.Uint64
}

// NewBlock arma un bloque. Copia la cabecera; las transacciones se comparten
// (son inmutables).
func NewBlock(header *Header, txs Transactions, justify []byte) *Block {
	return &Block{header: header.Copy(), transactions: append(Transactions(nil), txs...), justify: append([]byte(nil), justify...)}
}

// NewBlockWithRoots arma un bloque y completa TxRoot y JustifyHash a partir
// del contenido, usando hasher para la raíz. Lo usa el constructor de bloques.
func NewBlockWithRoots(header *Header, txs Transactions, justify []byte, hasher TrieHasher) (*Block, error) {
	h := header.Copy()
	root, err := DeriveRoot(txs, hasher)
	if err != nil {
		return nil, err
	}
	h.TxRoot = root
	h.JustifyHash = JustifyHash(justify)
	return NewBlock(h, txs, justify), nil
}

// JustifyHash calcula el hash del QC opaco (cero si no hay QC, p. ej. génesis).
func JustifyHash(justify []byte) Hash {
	if len(justify) == 0 {
		return Hash{}
	}
	return Keccak256Hash(justify)
}

// Header devuelve una COPIA de la cabecera.
func (b *Block) Header() *Header { return b.header.Copy() }

// HeaderRef devuelve la cabecera sin copiar; el llamador NO debe modificarla.
func (b *Block) HeaderRef() *Header { return b.header }

// Transactions devuelve las transacciones (no modificar el slice).
func (b *Block) Transactions() Transactions { return b.transactions }

// Justify devuelve el QC opaco del padre.
func (b *Block) Justify() []byte { return b.justify }

// Body devuelve el cuerpo del bloque.
func (b *Block) Body() *Body { return &Body{Transactions: b.transactions, Justify: b.justify} }

// Hash devuelve el hash de la cabecera (identificador del bloque).
func (b *Block) Hash() Hash { return b.header.Hash() }

// Number devuelve la altura.
func (b *Block) Number() uint64 { return b.header.Number }

// ParentHash devuelve el hash del padre.
func (b *Block) ParentHash() Hash { return b.header.ParentHash }

// StateRoot devuelve la raíz de estado posterior al bloque.
func (b *Block) StateRoot() Hash { return b.header.StateRoot }

// Transaction busca una tx por hash dentro del bloque.
func (b *Block) Transaction(h Hash) (*Transaction, int) {
	for i, tx := range b.transactions {
		if tx.Hash() == h {
			return tx, i
		}
	}
	return nil, -1
}

// EncodeRLP codifica el bloque como [header, [tx...], justify].
func (b *Block) EncodeRLP() []byte {
	// El bloque es una lista plana de 3 elementos (no [header, body]).
	txs, justify := b.Body().encodeParts()
	return EncodeList(b.header.EncodeRLP(), txs, justify)
}

// DecodeBlock decodifica un bloque completo.
func DecodeBlock(data []byte) (*Block, error) {
	if len(data) > MaxBlockSize {
		return nil, fmt.Errorf("bloque de %d bytes supera %d", len(data), MaxBlockSize)
	}
	it, err := DecodeRLP(data)
	if err != nil {
		return nil, err
	}
	f, err := it.ListN(3)
	if err != nil {
		return nil, err
	}
	h, err := decodeHeaderItem(f[0])
	if err != nil {
		return nil, err
	}
	body, err := decodeBodyItems(RLPItem{Kind: RLPList, List: f[1:]})
	if err != nil {
		return nil, err
	}
	b := &Block{header: h, transactions: body.Transactions, justify: body.Justify}
	b.size.Store(uint64(len(data)))
	return b, nil
}

// Size devuelve el tamaño codificado (cacheado).
func (b *Block) Size() uint64 {
	if s := b.size.Load(); s != 0 {
		return s
	}
	s := uint64(len(b.EncodeRLP()))
	b.size.Store(s)
	return s
}

// ValidateBody comprueba que el cuerpo coincida con los compromisos de la
// cabecera: TxRoot (recalculado con hasher) y JustifyHash, más los límites de
// tamaño. No ejecuta transacciones.
func (b *Block) ValidateBody(hasher TrieHasher) error {
	if len(b.justify) > MaxJustifySize {
		return newValidationError(nil, "block", "justify", "%d bytes supera %d", len(b.justify), MaxJustifySize)
	}
	if got := JustifyHash(b.justify); got != b.header.JustifyHash {
		return newValidationError(nil, "block", "justifyHash", "es %s, el cuerpo da %s", b.header.JustifyHash, got)
	}
	root, err := DeriveRoot(b.transactions, hasher)
	if err != nil {
		return err
	}
	if root != b.header.TxRoot {
		return newValidationError(nil, "block", "txRoot", "es %s, el cuerpo da %s", b.header.TxRoot, root)
	}
	return nil
}

// WithSeal devuelve un bloque nuevo con otra cabecera y el mismo cuerpo
// (p. ej. tras completar StateRoot luego de ejecutar).
func (b *Block) WithSeal(h *Header) *Block {
	return &Block{header: h.Copy(), transactions: b.transactions, justify: b.justify}
}

// String devuelve un resumen para logs.
func (b *Block) String() string {
	return fmt.Sprintf("Block{%s, %d txs}", b.header, len(b.transactions))
}
