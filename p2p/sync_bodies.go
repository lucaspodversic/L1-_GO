package p2p

// Sincronización de cuerpos de bloque.

import (
	"fmt"

	"github.com/l1/l1/types"
)

// BodyProvider suministra cuerpos.
type BodyProvider interface {
	BlockByHash(h types.Hash) (*types.Block, error)
}

// EncodeGetBodies pide cuerpos por hash.
func EncodeGetBodies(hashes []types.Hash) []byte {
	items := make([][]byte, len(hashes))
	for i, h := range hashes {
		items[i] = types.EncodeBytes(h[:])
	}
	body := types.EncodeList(items...)
	out := append([]byte{byte(SyncGetBodies)}, body...)
	return EncodeApp(AppSync, out)
}

// EncodeBodies serializa cuerpos.
func EncodeBodies(blocks []*types.Block) []byte {
	items := make([][]byte, len(blocks))
	for i, b := range blocks {
		items[i] = b.Body().EncodeRLP()
	}
	body := types.EncodeList(items...)
	out := append([]byte{byte(SyncBodies)}, body...)
	return EncodeApp(AppSync, out)
}

// DecodeBodyHashes parsea SyncGetBodies.
func DecodeBodyHashes(payload []byte) ([]types.Hash, error) {
	if len(payload) < 1 || SyncMsgType(payload[0]) != SyncGetBodies {
		return nil, fmt.Errorf("p2p: getbodies inválido")
	}
	it, err := types.DecodeRLP(payload[1:])
	if err != nil {
		return nil, err
	}
	items, err := it.Items()
	if err != nil {
		return nil, err
	}
	out := make([]types.Hash, 0, len(items))
	for _, it := range items {
		b, err := it.Bytes()
		if err != nil || len(b) != 32 {
			return nil, fmt.Errorf("p2p: hash inválido")
		}
		out = append(out, types.BytesToHash(b))
	}
	return out, nil
}

// ServeGetBodies responde.
func ServeGetBodies(p BodyProvider, payload []byte) []byte {
	hashes, err := DecodeBodyHashes(payload)
	if err != nil {
		return nil
	}
	var blocks []*types.Block
	for _, h := range hashes {
		b, err := p.BlockByHash(h)
		if err != nil || b == nil {
			continue
		}
		blocks = append(blocks, b)
	}
	return EncodeBodies(blocks)
}
