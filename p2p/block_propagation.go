package p2p

// Propagación de anuncios de bloques (hash) y petición del cuerpo completo.

import (
	"github.com/l1/l1/types"
)

// BlockPropagator anuncia y recibe hashes de bloques.
type BlockPropagator struct {
	gossip     *Gossip
	onAnnounce func(from PeerID, hash types.Hash)
}

// NewBlockPropagator crea el propagador.
func NewBlockPropagator(g *Gossip) *BlockPropagator {
	bp := &BlockPropagator{gossip: g}
	g.Subscribe(TopicBlocks, bp.handle)
	return bp
}

// OnAnnounce registra el callback.
func (bp *BlockPropagator) OnAnnounce(h func(PeerID, types.Hash)) { bp.onAnnounce = h }

// Announce difunde el hash de un bloque nuevo.
func (bp *BlockPropagator) Announce(hash types.Hash) error {
	return bp.gossip.Publish(TopicBlocks, hash[:], PeerID{})
}

func (bp *BlockPropagator) handle(from PeerID, _ string, data []byte) {
	if len(data) != 32 {
		return
	}
	h := types.BytesToHash(data)
	if bp.onAnnounce != nil {
		bp.onAnnounce(from, h)
	}
}
