package p2p

// Mensajes del protocolo de sincronización de cadena.

import (
	"encoding/binary"
	"fmt"

	"github.com/l1/l1/types"
)

// SyncMsgType subtipos dentro de AppSync.
type SyncMsgType byte

const (
	SyncGetHeaders SyncMsgType = 1
	SyncHeaders    SyncMsgType = 2
	SyncGetBodies  SyncMsgType = 3
	SyncBodies     SyncMsgType = 4
	SyncGetState   SyncMsgType = 5
	SyncState      SyncMsgType = 6
	SyncStatus     SyncMsgType = 7
)

// StatusMsg anuncia la punta de la cadena.
type StatusMsg struct {
	Genesis   types.Hash
	Head      types.Hash
	Number    uint64
	Finalized types.Hash
}

// EncodeStatus serializa StatusMsg.
func EncodeStatus(s StatusMsg) []byte {
	b := []byte{byte(SyncStatus)}
	b = append(b, s.Genesis[:]...)
	b = append(b, s.Head[:]...)
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], s.Number)
	b = append(b, n[:]...)
	b = append(b, s.Finalized[:]...)
	return EncodeApp(AppSync, b)
}

// DecodeStatus parsea.
func DecodeStatus(payload []byte) (StatusMsg, error) {
	if len(payload) < 1+32+32+8+32 || SyncMsgType(payload[0]) != SyncStatus {
		return StatusMsg{}, fmt.Errorf("p2p: status inválido")
	}
	var s StatusMsg
	copy(s.Genesis[:], payload[1:33])
	copy(s.Head[:], payload[33:65])
	s.Number = binary.BigEndian.Uint64(payload[65:73])
	copy(s.Finalized[:], payload[73:105])
	return s, nil
}

// EncodeGetHeaders pide cabeceras desde from, count.
func EncodeGetHeaders(from, count uint64) []byte {
	var b [17]byte
	b[0] = byte(SyncGetHeaders)
	binary.BigEndian.PutUint64(b[1:], from)
	binary.BigEndian.PutUint64(b[9:], count)
	return EncodeApp(AppSync, b[:])
}
