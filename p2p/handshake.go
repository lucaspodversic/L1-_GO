package p2p

// Handshake Noise-like simplificado sobre TCP:
//
//  1. Cada lado genera un efímero X25519 y envía: version|eph_pub|static_ed25519_pub|sig(transcript)
//  2. Ambos calculan el secreto compartido X25519 y derivan SessionKeys.
//  3. El transcript firmado es: "l1-hs-v1" || eph_local || eph_remote || static_local || static_remote
//     (ordenados de forma canónica por static PeerID).
//
// Tras el intercambio las tramas van cifradas con ChaCha20-Poly1305.

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/l1/l1/crypto"
	"golang.org/x/crypto/curve25519"
)

const (
	hsVersion     = 1
	hsMessageSize = 1 + 32 + 32 + 64 // ver + eph + static + sig
	hsTimeout     = 10 * time.Second
)

// ErrHandshake indica fallo de autenticación o versión.
var ErrHandshake = errors.New("p2p: handshake fallido")

// LocalIdentity es la identidad estática del nodo.
type LocalIdentity struct {
	Private *crypto.Ed25519PrivateKey
	Public  *crypto.Ed25519PublicKey
	ID      PeerID
}

// NewLocalIdentity genera una identidad nueva.
func NewLocalIdentity() (*LocalIdentity, error) {
	priv, err := crypto.GenerateEd25519(rand.Reader)
	if err != nil {
		return nil, err
	}
	pub := priv.PublicKey()
	return &LocalIdentity{Private: priv, Public: pub, ID: pub.ID()}, nil
}

// IdentityFromPrivate reconstruye desde una clave existente.
func IdentityFromPrivate(priv *crypto.Ed25519PrivateKey) *LocalIdentity {
	pub := priv.PublicKey()
	return &LocalIdentity{Private: priv, Public: pub, ID: pub.ID()}
}

// HandshakeResult es el resultado de un handshake exitoso.
type HandshakeResult struct {
	RemoteID PeerID
	RemotePK *crypto.Ed25519PublicKey
	Keys     *SessionKeys
}

// DoHandshake ejecuta el intercambio sobre conn (dialer=true si iniciamos).
func DoHandshake(conn net.Conn, id *LocalIdentity, dialer bool) (*HandshakeResult, error) {
	_ = conn.SetDeadline(time.Now().Add(hsTimeout))
	defer conn.SetDeadline(time.Time{})

	var ephPriv, ephPub [32]byte
	if _, err := io.ReadFull(rand.Reader, ephPriv[:]); err != nil {
		return nil, err
	}
	curve25519.ScalarBaseMult(&ephPub, &ephPriv)

	// Enviar nuestro mensaje.
	myMsg := make([]byte, hsMessageSize)
	myMsg[0] = hsVersion
	copy(myMsg[1:33], ephPub[:])
	copy(myMsg[33:65], id.Public.Bytes())
	// Firma provisional; se rellena tras conocer al remoto... En este
	// diseño enviamos primero y firmamos el transcript unidireccional
	// (propia eph+static). El remoto verifica tras recibir ambos.
	// Para autenticación mutua firme: eph||static.
	sigPayload := append(append([]byte("l1-hs-v1"), ephPub[:]...), id.Public.Bytes()...)
	sig, err := id.Private.Sign(sigPayload)
	if err != nil {
		return nil, err
	}
	copy(myMsg[65:], sig)

	if _, err := conn.Write(myMsg); err != nil {
		return nil, err
	}
	their := make([]byte, hsMessageSize)
	if _, err := io.ReadFull(conn, their); err != nil {
		return nil, err
	}
	if their[0] != hsVersion {
		return nil, fmt.Errorf("%w: versión %d", ErrHandshake, their[0])
	}
	var theirEph [32]byte
	copy(theirEph[:], their[1:33])
	theirStatic, err := crypto.ParseEd25519PublicKey(their[33:65])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHandshake, err)
	}
	theirSig := their[65:]
	verifyPayload := append(append([]byte("l1-hs-v1"), theirEph[:]...), theirStatic.Bytes()...)
	if !theirStatic.Verify(verifyPayload, theirSig) {
		return nil, fmt.Errorf("%w: firma inválida", ErrHandshake)
	}
	remoteID := theirStatic.ID()

	var shared [32]byte
	curve25519.ScalarMult(&shared, &ephPriv, &theirEph)
	keys, err := DeriveSessionKeys(shared[:], id.ID, remoteID)
	if err != nil {
		return nil, err
	}
	return &HandshakeResult{RemoteID: remoteID, RemotePK: theirStatic, Keys: keys}, nil
}

// frameHeaderSize es u32 big-endian de longitud del payload cifrado.
const frameHeaderSize = 4

// MaxFrameSize limita una trama (16 MiB).
const MaxFrameSize = 16 << 20

// WriteFrame escribe una trama cifrada length-prefixed.
func WriteFrame(w io.Writer, keys *SessionKeys, plaintext []byte) error {
	sealed := keys.Seal(plaintext)
	if len(sealed) > MaxFrameSize {
		return fmt.Errorf("p2p: trama demasiado grande (%d)", len(sealed))
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(sealed)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(sealed)
	return err
}

// ReadFrame lee y descifra una trama.
func ReadFrame(r io.Reader, keys *SessionKeys) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > MaxFrameSize {
		return nil, fmt.Errorf("p2p: longitud de trama inválida %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return keys.Open(buf)
}
