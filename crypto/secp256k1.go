package crypto

// secp256k1 con firmas ECDSA recuperables es el esquema de las cuentas de
// usuario, idéntico a Ethereum: la dirección es Keccak256(X||Y)[12:] de la
// clave pública sin comprimir y el remitente de una transacción se recupera
// de la firma (no viaja en la transacción). Las firmas son deterministas
// (RFC 6979) y siempre con S bajo (decred normaliza S ≤ n/2), lo que elimina
// la maleabilidad.
//
// Formatos:
//   - Firma "Ethereum": R(32) || S(32) || V(1) con V ∈ {0,1} (types.Signature).
//   - Formato compacto de decred: [27+V(+4)] || R || S; se convierte aquí.

import (
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/l1/l1/types"
)

// compactMagic es el desplazamiento del byte de recuperación en el formato
// compacto de decred/Bitcoin (27 = 0x1b).
const compactMagic = 27

// Secp256k1PrivateKey es una clave privada secp256k1 (escalar en [1, n-1]).
type Secp256k1PrivateKey struct {
	k *secp256k1.PrivateKey
}

// Secp256k1PublicKey es un punto de la curva secp256k1.
type Secp256k1PublicKey struct {
	k *secp256k1.PublicKey
}

// GenerateSecp256k1 genera una clave nueva usando r como fuente de entropía.
func GenerateSecp256k1(r io.Reader) (*Secp256k1PrivateKey, error) {
	k, err := secp256k1.GeneratePrivateKeyFromRand(r)
	if err != nil {
		return nil, err
	}
	return &Secp256k1PrivateKey{k: k}, nil
}

// Secp256k1FromBytes construye una clave a partir de 32 bytes big-endian.
// Rechaza 0 y valores ≥ n (el orden del grupo), en lugar de reducirlos
// silenciosamente como haría la biblioteca.
func Secp256k1FromBytes(b []byte) (*Secp256k1PrivateKey, error) {
	if len(b) != 32 {
		return nil, fmt.Errorf("%w: secp256k1 de %d bytes", ErrInvalidPrivateKey, len(b))
	}
	var s secp256k1.ModNScalar
	if overflow := s.SetByteSlice(b); overflow || s.IsZero() {
		return nil, ErrInvalidPrivateKey
	}
	return &Secp256k1PrivateKey{k: secp256k1.NewPrivateKey(&s)}, nil
}

// HexToSecp256k1 parsea una clave privada en hex (con o sin 0x).
func HexToSecp256k1(s string) (*Secp256k1PrivateKey, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPrivateKey, err)
	}
	return Secp256k1FromBytes(b)
}

// ParseSecp256k1PublicKey acepta claves comprimidas (33 bytes), sin comprimir
// (65 bytes con prefijo 0x04) o crudas X||Y (64 bytes, formato de ecrecover).
func ParseSecp256k1PublicKey(b []byte) (*Secp256k1PublicKey, error) {
	if len(b) == 64 {
		b = append([]byte{0x04}, b...)
	}
	k, err := secp256k1.ParsePubKey(b)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPublicKey, err)
	}
	return &Secp256k1PublicKey{k: k}, nil
}

// Scheme implementa PrivateKey.
func (p *Secp256k1PrivateKey) Scheme() KeyType { return types.SchemeSecp256k1 }

// Public implementa PrivateKey.
func (p *Secp256k1PrivateKey) Public() PublicKey { return p.PublicKey() }

// PublicKey devuelve la clave pública con su tipo concreto.
func (p *Secp256k1PrivateKey) PublicKey() *Secp256k1PublicKey {
	return &Secp256k1PublicKey{k: p.k.PubKey()}
}

// Address devuelve la dirección de cuenta asociada a la clave.
func (p *Secp256k1PrivateKey) Address() types.Address { return p.PublicKey().Address() }

// Bytes implementa PrivateKey: 32 bytes big-endian.
func (p *Secp256k1PrivateKey) Bytes() []byte { return p.k.Serialize() }

// Hex devuelve la clave privada en hex con 0x. ¡Material secreto!
func (p *Secp256k1PrivateKey) Hex() string { return "0x" + hex.EncodeToString(p.Bytes()) }

// Sign implementa PrivateKey: firma Keccak256(msg) y devuelve 65 bytes R||S||V.
func (p *Secp256k1PrivateKey) Sign(msg []byte) ([]byte, error) {
	sig, err := p.SignHash(Keccak256Hash(msg))
	if err != nil {
		return nil, err
	}
	return sig.Bytes(), nil
}

// SignHash firma un hash de 32 bytes ya calculado y devuelve la firma
// recuperable en formato Ethereum (V ∈ {0,1}).
func (p *Secp256k1PrivateKey) SignHash(h types.Hash) (types.Signature, error) {
	// isCompressedKey=false → byte de recuperación = 27 + recid.
	c := ecdsa.SignCompact(p.k, h[:], false)
	recid := c[0] - compactMagic
	if recid > 1 {
		// recid 2/3 sólo ocurre si R ≥ n (probabilidad ~2^-127); Ethereum no
		// puede representarlo con V ∈ {0,1}, así que se reporta como error.
		return types.Signature{}, fmt.Errorf("crypto: id de recuperación %d no representable", recid)
	}
	var sig types.Signature
	copy(sig[0:64], c[1:65])
	sig[64] = recid
	return sig, nil
}

// Zero borra el escalar secreto de memoria (best-effort).
func (p *Secp256k1PrivateKey) Zero() { p.k.Zero() }

// Scheme implementa PublicKey.
func (k *Secp256k1PublicKey) Scheme() KeyType { return types.SchemeSecp256k1 }

// Bytes implementa PublicKey: formato comprimido de 33 bytes.
func (k *Secp256k1PublicKey) Bytes() []byte { return k.k.SerializeCompressed() }

// Uncompressed devuelve el formato sin comprimir de 65 bytes (0x04||X||Y).
func (k *Secp256k1PublicKey) Uncompressed() []byte { return k.k.SerializeUncompressed() }

// Address devuelve Keccak256(X||Y)[12:], la dirección de cuenta.
func (k *Secp256k1PublicKey) Address() types.Address {
	return PubkeyBytesToAddress(k.Uncompressed())
}

// Verify implementa PublicKey: acepta firmas de 64 (R||S) o 65 bytes
// (R||S||V) sobre Keccak256(msg).
func (k *Secp256k1PublicKey) Verify(msg, sig []byte) bool {
	return k.VerifyHash(Keccak256Hash(msg), sig)
}

// VerifyHash verifica una firma ECDSA sobre un hash ya calculado. Exige S
// bajo para rechazar firmas maleables.
func (k *Secp256k1PublicKey) VerifyHash(h types.Hash, sig []byte) bool {
	if len(sig) != 64 && len(sig) != 65 {
		return false
	}
	var r, s secp256k1.ModNScalar
	if r.SetByteSlice(sig[0:32]) || s.SetByteSlice(sig[32:64]) {
		return false // R o S ≥ n
	}
	if r.IsZero() || s.IsZero() || s.IsOverHalfOrder() {
		return false
	}
	return ecdsa.NewSignature(&r, &s).Verify(h[:], k.k)
}

// Equal implementa PublicKey.
func (k *Secp256k1PublicKey) Equal(o PublicKey) bool { return equalPub(k, o) }

// PubkeyBytesToAddress calcula la dirección a partir de una clave sin
// comprimir de 65 bytes (0x04||X||Y) o cruda de 64 bytes (X||Y).
func PubkeyBytesToAddress(pub []byte) types.Address {
	if len(pub) == 65 {
		pub = pub[1:]
	}
	return types.BytesToAddress(Keccak256(pub)[12:])
}

// RecoverPubkey recupera la clave pública que produjo sig sobre h.
// sig debe estar en formato R||S||V con V ∈ {0,1}.
func RecoverPubkey(h types.Hash, sig types.Signature) (*Secp256k1PublicKey, error) {
	if sig.V() > 1 {
		return nil, types.ErrInvalidSignature
	}
	// Convertimos al formato compacto de decred: [27+V] || R || S.
	var c [65]byte
	c[0] = compactMagic + sig.V()
	copy(c[1:], sig[0:64])
	pub, _, err := ecdsa.RecoverCompact(c[:], h[:])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", types.ErrInvalidSignature, err)
	}
	return &Secp256k1PublicKey{k: pub}, nil
}

// RecoverAddress recupera la dirección del firmante de h.
func RecoverAddress(h types.Hash, sig types.Signature) (types.Address, error) {
	pub, err := RecoverPubkey(h, sig)
	if err != nil {
		return types.Address{}, err
	}
	return pub.Address(), nil
}

// Ecrecover implementa la semántica del precompilado ECRECOVER (0x01):
// devuelve la clave sin comprimir de 65 bytes. No exige S bajo (el
// precompilado de Ethereum acepta firmas "altas"), pero sí R,S en [1,n-1].
func Ecrecover(h types.Hash, sig types.Signature) ([]byte, error) {
	if !sig.ValidateValues(false) {
		return nil, types.ErrInvalidSignature
	}
	pub, err := RecoverPubkey(h, sig)
	if err != nil {
		return nil, err
	}
	return pub.Uncompressed(), nil
}
