package node

// BlockBuilder envuelve ExecutorService.BuildBlock con parámetros del nodo.

import (
	"time"

	"github.com/l1/l1/consensus"
	"github.com/l1/l1/execution"
	"github.com/l1/l1/types"
)

// BlockBuilder construye bloques de propuesta.
type BlockBuilder struct {
	exec *execution.ExecutorService
	key  *consensus.ValidatorKey
}

// NewBlockBuilder crea el builder.
func NewBlockBuilder(exec *execution.ExecutorService, key *consensus.ValidatorKey) *BlockBuilder {
	return &BlockBuilder{exec: exec, key: key}
}

// Build construye un hijo de parent.
func (b *BlockBuilder) Build(parent *types.Header, epoch, view uint64, random types.Hash, valsHash types.Hash, justify []byte, txs execution.TxIterator) (*execution.BuildResult, error) {
	coinbase := types.Address{}
	if b.key != nil {
		coinbase = b.key.Address
	}
	return b.exec.BuildBlock(parent, execution.BuildParams{
		Coinbase: coinbase, Timestamp: uint64(time.Now().Unix()),
		Epoch: epoch, View: view, Random: random, ValidatorsHash: valsHash,
		Justify: justify, GasLimit: parent.GasLimit,
	}, txs)
}
