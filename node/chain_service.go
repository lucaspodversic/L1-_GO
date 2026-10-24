package node

// ChainService es la vista de cadena que consumen RPC y sync: BlockStore +
// estado + cabecera actual.

import (
	"sync"

	"github.com/l1/l1/storage"
	"github.com/l1/l1/types"
)

// ChainService envuelve el almacén de bloques.
type ChainService struct {
	mu      sync.RWMutex
	db      *storage.Database
	blocks  *storage.BlockStore
	genesis *types.Block
}

// NewChainService crea el servicio.
func NewChainService(db *storage.Database, genesis *types.Block) *ChainService {
	return &ChainService{db: db, blocks: db.Blocks, genesis: genesis}
}

// GenesisHash hash del génesis.
func (c *ChainService) GenesisHash() types.Hash { return c.genesis.Hash() }

// GenesisBlock bloque 0.
func (c *ChainService) GenesisBlock() *types.Block { return c.genesis }

// Blocks expone el BlockStore.
func (c *ChainService) Blocks() *storage.BlockStore { return c.blocks }

// DB expone la base.
func (c *ChainService) DB() *storage.Database { return c.db }

// CurrentHeader punta canónica.
func (c *ChainService) CurrentHeader() *types.Header { return c.blocks.CurrentHeader() }

// CurrentBlock bloque canónico punta.
func (c *ChainService) CurrentBlock() (*types.Block, error) { return c.blocks.CurrentBlock(), nil }

// HeaderByNumber implementa p2p.HeaderProvider.
func (c *ChainService) HeaderByNumber(n uint64) (*types.Header, error) {
	return c.blocks.HeaderByNumber(n)
}

// HeaderByHash por hash.
func (c *ChainService) HeaderByHash(h types.Hash) (*types.Header, error) {
	return c.blocks.HeaderByHash(h)
}

// BlockByHash implementa BodyProvider.
func (c *ChainService) BlockByHash(h types.Hash) (*types.Block, error) {
	return c.blocks.BlockByHash(h)
}

// BlockByNumber por altura.
func (c *ChainService) BlockByNumber(n uint64) (*types.Block, error) {
	return c.blocks.BlockByNumber(n)
}

// FinalizedHeader cabecera finalizada.
func (c *ChainService) FinalizedHeader() (*types.Header, error) {
	return c.blocks.FinalizedHeader(), nil
}

// WriteBlock persiste (para sync).
func (c *ChainService) WriteBlock(b *types.Block, receipts types.Receipts, canonical bool) error {
	return c.blocks.WriteBlock(b, receipts, canonical)
}

// StateAt abre el estado en root.
func (c *ChainService) StateAt(root types.Hash) (*storage.StateDB, error) {
	return storage.New(root, c.db.State)
}

// Transaction busca una tx.
func (c *ChainService) Transaction(hash types.Hash) (*types.Transaction, *storage.TxLookupEntry, error) {
	return c.blocks.Transaction(hash)
}

// Receipts de un bloque.
func (c *ChainService) Receipts(hash types.Hash) (types.Receipts, error) {
	return c.blocks.Receipts(hash)
}
