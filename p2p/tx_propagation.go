package p2p

// Propagación de transacciones (anuncio por hash o gossip del RLP completo
// para txs pequeñas).

import (
	"github.com/l1/l1/types"
)

// TxPropagator difunde transacciones.
type TxPropagator struct {
	gossip *Gossip
	onTx   func(from PeerID, raw []byte)
}

// NewTxPropagator crea el propagador.
func NewTxPropagator(g *Gossip) *TxPropagator {
	tp := &TxPropagator{gossip: g}
	g.Subscribe(TopicTxs, tp.handle)
	return tp
}

// OnTx registra el callback de recepción.
func (tp *TxPropagator) OnTx(h func(PeerID, []byte)) { tp.onTx = h }

// Announce difunde el encoding de una tx.
func (tp *TxPropagator) Announce(tx *types.Transaction) error {
	raw := tx.MustMarshalBinary()
	return tp.gossip.Publish(TopicTxs, raw, PeerID{})
}

func (tp *TxPropagator) handle(from PeerID, _ string, data []byte) {
	if tp.onTx != nil {
		tp.onTx(from, data)
	}
}
