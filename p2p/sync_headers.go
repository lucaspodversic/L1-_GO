package p2p

// Sincronización de cabeceras.

import (
	"encoding/binary"
	"fmt"

	"github.com/l1/l1/types"
)

// HeaderProvider suministra cabeceras canónicas.
type HeaderProvider interface {
	HeaderByNumber(n uint64) (*types.Header, error)
	CurrentHeader() *types.Header
}

// EncodeHeaders serializa una lista de cabeceras RLP.
func EncodeHeaders(headers []*types.Header) []byte {
	parts := make([][]byte, len(headers))
	for i, h := range headers {
		parts[i] = h.EncodeRLP()
	}
	body := types.EncodeList(parts...)
	out := make([]byte, 1+len(body))
	out[0] = byte(SyncHeaders)
	copy(out[1:], body)
	return EncodeApp(AppSync, out)
}

// DecodeHeaders parsea la lista.
func DecodeHeaders(payload []byte) ([]*types.Header, error) {
	if len(payload) < 1 || SyncMsgType(payload[0]) != SyncHeaders {
		return nil, fmt.Errorf("p2p: headers inválidos")
	}
	it, err := types.DecodeRLP(payload[1:])
	if err != nil {
		return nil, err
	}
	items, err := it.Items()
	if err != nil {
		return nil, err
	}
	out := make([]*types.Header, 0, len(items))
	for _, it := range items {
		h, err := types.DecodeHeader(it.Raw)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, nil
}

// ServeGetHeaders responde a SyncGetHeaders.
func ServeGetHeaders(p HeaderProvider, payload []byte) []byte {
	if len(payload) < 17 {
		return nil
	}
	from := binary.BigEndian.Uint64(payload[1:9])
	count := binary.BigEndian.Uint64(payload[9:17])
	if count > 256 {
		count = 256
	}
	var headers []*types.Header
	for i := uint64(0); i < count; i++ {
		h, err := p.HeaderByNumber(from + i)
		if err != nil || h == nil {
			break
		}
		headers = append(headers, h)
	}
	return EncodeHeaders(headers)
}
