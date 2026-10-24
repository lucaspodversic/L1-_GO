package p2p

// PeerID es la identidad de un nodo en la red: hash Keccak256 de su clave
// pública Ed25519. Se usa en discovery, ban-list y direccionamiento.

import (
	"encoding/hex"
	"fmt"

	"github.com/l1/l1/crypto"
	"github.com/l1/l1/types"
)

// PeerID es un hash de 32 bytes.
type PeerID = types.Hash

// PeerIDFromPublic deriva el PeerID de una clave Ed25519.
func PeerIDFromPublic(pk *crypto.Ed25519PublicKey) PeerID {
	return pk.ID()
}

// PeerIDFromBytes interpreta 32 bytes como PeerID.
func PeerIDFromBytes(b []byte) (PeerID, error) {
	if len(b) != 32 {
		return PeerID{}, fmt.Errorf("p2p: peer id de %d bytes", len(b))
	}
	return types.BytesToHash(b), nil
}

// PeerIDFromHex parsea un PeerID hex (con o sin 0x).
func PeerIDFromHex(s string) (PeerID, error) {
	return types.HexToHash(s)
}

// ShortID devuelve los 8 primeros bytes hex para logs.
func ShortID(id PeerID) string {
	return hex.EncodeToString(id[:8])
}
