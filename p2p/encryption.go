package p2p

// Cifrado de sesión: tras el handshake X25519+Ed25519 se derivan dos claves
// ChaCha20-Poly1305 (una por dirección) con HKDF-SHA256. Cada trama lleva
// un nonce de 12 bytes (contador little-endian) y el tag Poly1305.

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"crypto/sha256"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// ErrDecrypt indica fallo de autenticación de una trama.
var ErrDecrypt = errors.New("p2p: fallo al descifrar trama")

// SessionKeys contiene las dos direcciones de cifrado.
type SessionKeys struct {
	Send  cipher.AEAD
	Recv  cipher.AEAD
	sendN uint64
	recvN uint64
}

// DeriveSessionKeys deriva las claves a partir del secreto compartido y los
// PeerID (ordenados) para que ambos extremos coincidan.
func DeriveSessionKeys(sharedSecret []byte, local, remote PeerID) (*SessionKeys, error) {
	// Orden canónico: el de PeerID menor es "A".
	a, b := local, remote
	localIsA := true
	if bytesCmp(remote[:], local[:]) < 0 {
		a, b = remote, local
		localIsA = false
	}
	info := append(append([]byte("l1-p2p-session-v1"), a[:]...), b[:]...)
	r := hkdf.New(sha256.New, sharedSecret, nil, info)
	keyA := make([]byte, chacha20poly1305.KeySize)
	keyB := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(r, keyA); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(r, keyB); err != nil {
		return nil, err
	}
	aeadA, err := chacha20poly1305.New(keyA)
	if err != nil {
		return nil, err
	}
	aeadB, err := chacha20poly1305.New(keyB)
	if err != nil {
		return nil, err
	}
	sk := &SessionKeys{}
	if localIsA {
		sk.Send, sk.Recv = aeadA, aeadB
	} else {
		sk.Send, sk.Recv = aeadB, aeadA
	}
	return sk, nil
}

func bytesCmp(a, b []byte) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return len(a) - len(b)
}

// Seal cifra plaintext y devuelve nonce||ciphertext+tag.
func (s *SessionKeys) Seal(plaintext []byte) []byte {
	nonce := make([]byte, chacha20poly1305.NonceSize)
	binary.LittleEndian.PutUint64(nonce, s.sendN)
	s.sendN++
	out := make([]byte, len(nonce), len(nonce)+len(plaintext)+s.Send.Overhead())
	copy(out, nonce)
	return s.Send.Seal(out, nonce, plaintext, nil)
}

// Open descifra una trama nonce||ciphertext+tag.
func (s *SessionKeys) Open(frame []byte) ([]byte, error) {
	if len(frame) < chacha20poly1305.NonceSize+s.Recv.Overhead() {
		return nil, ErrDecrypt
	}
	nonce := frame[:chacha20poly1305.NonceSize]
	n := binary.LittleEndian.Uint64(nonce)
	if n < s.recvN {
		return nil, fmt.Errorf("%w: nonce reutilizado", ErrDecrypt)
	}
	pt, err := s.Recv.Open(nil, nonce, frame[chacha20poly1305.NonceSize:], nil)
	if err != nil {
		return nil, ErrDecrypt
	}
	s.recvN = n + 1
	return pt, nil
}
