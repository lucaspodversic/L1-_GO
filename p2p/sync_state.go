package p2p

// Sincronización de nodos de estado (snap-like simplificado): se piden
// nodos del trie por hash.

import (
	"fmt"

	"github.com/l1/l1/storage"
	"github.com/l1/l1/types"
)

// StateNodeProvider lee nodos del trie.
type StateNodeProvider interface {
	Node(hash types.Hash) ([]byte, error)
}

// EncodeGetState pide nodos.
func EncodeGetState(hashes []types.Hash) []byte {
	items := make([][]byte, len(hashes))
	for i, h := range hashes {
		items[i] = types.EncodeBytes(h[:])
	}
	body := types.EncodeList(items...)
	return EncodeApp(AppSync, append([]byte{byte(SyncGetState)}, body...))
}

// EncodeStateNodes responde con pares (hash, rlp).
func EncodeStateNodes(nodes map[types.Hash][]byte) []byte {
	items := make([][]byte, 0, len(nodes))
	for h, n := range nodes {
		items = append(items, types.EncodeList(types.EncodeBytes(h[:]), types.EncodeBytes(n)))
	}
	body := types.EncodeList(items...)
	return EncodeApp(AppSync, append([]byte{byte(SyncState)}, body...))
}

// ServeGetState responde a SyncGetState.
func ServeGetState(p StateNodeProvider, payload []byte) []byte {
	if len(payload) < 1 || SyncMsgType(payload[0]) != SyncGetState {
		return nil
	}
	it, err := types.DecodeRLP(payload[1:])
	if err != nil {
		return nil
	}
	items, err := it.Items()
	if err != nil {
		return nil
	}
	out := make(map[types.Hash][]byte)
	for _, it := range items {
		b, err := it.Bytes()
		if err != nil || len(b) != 32 {
			continue
		}
		h := types.BytesToHash(b)
		n, err := p.Node(h)
		if err == nil {
			out[h] = n
		}
	}
	return EncodeStateNodes(out)
}

// Ensure NodeDatabase satisface la interfaz.
var _ StateNodeProvider = (*storage.NodeDatabase)(nil)

// DecodeStateNodes parsea la respuesta (para el cliente).
func DecodeStateNodes(payload []byte) (map[types.Hash][]byte, error) {
	if len(payload) < 1 || SyncMsgType(payload[0]) != SyncState {
		return nil, fmt.Errorf("p2p: state inválido")
	}
	it, err := types.DecodeRLP(payload[1:])
	if err != nil {
		return nil, err
	}
	items, err := it.Items()
	if err != nil {
		return nil, err
	}
	out := make(map[types.Hash][]byte, len(items))
	for _, it := range items {
		f, err := it.ListN(2)
		if err != nil {
			continue
		}
		hb, err := f[0].Bytes()
		if err != nil || len(hb) != 32 {
			continue
		}
		nb, err := f[1].BytesCopy()
		if err != nil {
			continue
		}
		out[types.BytesToHash(hb)] = nb
	}
	return out, nil
}
