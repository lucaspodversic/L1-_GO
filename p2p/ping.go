package p2p

// Ping/Pong para medir RTT y mantener viva la conexión.

import (
	"encoding/binary"
	"time"
)

// EncodePing codifica un ping con timestamp unix nano.
func EncodePing() []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(time.Now().UnixNano()))
	return EncodeApp(AppPing, b[:])
}

// EncodePong responde con el mismo payload.
func EncodePong(payload []byte) []byte {
	return EncodeApp(AppPong, payload)
}

// PingRTT calcula el RTT a partir del payload del pong.
func PingRTT(payload []byte) (time.Duration, bool) {
	if len(payload) < 8 {
		return 0, false
	}
	sent := int64(binary.BigEndian.Uint64(payload[:8]))
	return time.Duration(time.Now().UnixNano() - sent), true
}
