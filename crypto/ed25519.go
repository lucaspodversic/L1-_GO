package crypto

// Ed25519 (RFC 8032) se usa para la identidad de los nodos en la red P2P:
// handshake autenticado y firma de registros de descubrimiento. Es rápido,
// determinista y con claves de 32 bytes. El PeerID de un nodo se deriva del
// hash de su clave pública Ed25519.

import (
	"crypto/ed25519"
	"fmt"
	"io"

	"github.com/l1/l1/types"
)

// Ed25519PrivateKey envuelve una clave privada Ed25519 (semilla de 32 bytes
// expandida a 64 por la biblioteca estándar).
type Ed25519PrivateKey struct {
	key ed25519.PrivateKey
}

// Ed25519PublicKey envuelve una clave pública Ed25519 de 32 bytes.
type Ed25519PublicKey struct {
	key ed25519.PublicKey
}

// GenerateEd25519 genera una clave Ed25519 nueva leyendo 32 bytes de r.
func GenerateEd25519(r io.Reader) (*Ed25519PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(r)
	if err != nil {
		return nil, err
	}
	return &Ed25519PrivateKey{key: priv}, nil
}

// Ed25519FromSeed reconstruye una clave a partir de su semilla de 32 bytes.
func Ed25519FromSeed(seed []byte) (*Ed25519PrivateKey, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%w: semilla ed25519 de %d bytes", ErrInvalidPrivateKey, len(seed))
	}
	return &Ed25519PrivateKey{key: ed25519.NewKeyFromSeed(seed)}, nil
}

// ParseEd25519PublicKey parsea una clave pública de 32 bytes.
func ParseEd25519PublicKey(b []byte) (*Ed25519PublicKey, error) {
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: ed25519 de %d bytes", ErrInvalidPublicKey, len(b))
	}
	return &Ed25519PublicKey{key: append(ed25519.PublicKey(nil), b...)}, nil
}

// Scheme implementa PrivateKey.
func (k *Ed25519PrivateKey) Scheme() KeyType { return types.SchemeEd25519 }

// Public implementa PrivateKey.
func (k *Ed25519PrivateKey) Public() PublicKey { return k.PublicKey() }

// PublicKey devuelve la clave pública con su tipo concreto.
func (k *Ed25519PrivateKey) PublicKey() *Ed25519PublicKey {
	return &Ed25519PublicKey{key: k.key.Public().(ed25519.PublicKey)}
}

// Sign implementa PrivateKey: firma msg tal cual (Ed25519 hashea internamente
// con SHA-512). Nunca falla.
func (k *Ed25519PrivateKey) Sign(msg []byte) ([]byte, error) { return ed25519.Sign(k.key, msg), nil }

// Bytes implementa PrivateKey: devuelve la semilla de 32 bytes.
func (k *Ed25519PrivateKey) Bytes() []byte { return append([]byte(nil), k.key.Seed()...) }

// Std devuelve la clave en el tipo de la biblioteca estándar (para crypto/tls
// u otras APIs que la acepten).
func (k *Ed25519PrivateKey) Std() ed25519.PrivateKey { return k.key }

// Scheme implementa PublicKey.
func (p *Ed25519PublicKey) Scheme() KeyType { return types.SchemeEd25519 }

// Bytes implementa PublicKey.
func (p *Ed25519PublicKey) Bytes() []byte { return append([]byte(nil), p.key...) }

// Verify implementa PublicKey.
func (p *Ed25519PublicKey) Verify(msg, sig []byte) bool {
	return len(sig) == ed25519.SignatureSize && ed25519.Verify(p.key, msg, sig)
}

// Equal implementa PublicKey.
func (p *Ed25519PublicKey) Equal(o PublicKey) bool { return equalPub(p, o) }

// Std devuelve la clave en el tipo de la biblioteca estándar.
func (p *Ed25519PublicKey) Std() ed25519.PublicKey { return p.key }

// ID devuelve el identificador de nodo: BLAKE3 de la clave pública con
// separación de dominio. Lo usa la capa P2P como PeerID.
func (p *Ed25519PublicKey) ID() types.Hash {
	return types.Hash(Blake3([]byte("l1/peer-id/v1"), p.key))
}
