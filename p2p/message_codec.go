package p2p

// Codec length-prefixed: type(1) || payload.

import (
	"encoding/binary"
	"fmt"
)

// EncodeApp empaqueta tipo + payload.
func EncodeApp(t AppMsgType, payload []byte) []byte {
	out := make([]byte, 1+len(payload))
	out[0] = byte(t)
	copy(out[1:], payload)
	return out
}

// DecodeApp separa tipo y payload.
func DecodeApp(b []byte) (AppMsgType, []byte, error) {
	if len(b) < 1 {
		return 0, nil, fmt.Errorf("p2p: mensaje vacío")
	}
	return AppMsgType(b[0]), b[1:], nil
}

// EncodeReq codifica id(u64 BE) || payload.
func EncodeReq(id uint64, payload []byte) []byte {
	out := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint64(out, id)
	copy(out[8:], payload)
	return out
}

// DecodeReq es la inversa.
func DecodeReq(b []byte) (uint64, []byte, error) {
	if len(b) < 8 {
		return 0, nil, fmt.Errorf("p2p: req corto")
	}
	return binary.BigEndian.Uint64(b[:8]), b[8:], nil
}
