package crypto

// Abstracción común de claves. Cada esquema (secp256k1, Ed25519, BLS12-381)
// implementa PrivateKey/PublicKey, de modo que el resto del sistema (CLI,
// keystore, consenso, P2P) maneje claves de forma uniforme. También se
// incluye un formato de archivo de claves cifrado (scrypt +
// XChaCha20-Poly1305) para guardar claves en disco protegidas por contraseña.

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/l1/l1/types"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/scrypt"
)

// KeyType es el esquema de firma de una clave; reutiliza types.SigScheme
// para que el identificador sea el mismo en claves y en firmas serializadas.
type KeyType = types.SigScheme

// Errores comunes de manejo de claves.
var (
	// ErrInvalidPrivateKey indica bytes de clave privada malformados o fuera de rango.
	ErrInvalidPrivateKey = errors.New("crypto: clave privada inválida")
	// ErrInvalidPublicKey indica una clave pública malformada o fuera de la curva/subgrupo.
	ErrInvalidPublicKey = errors.New("crypto: clave pública inválida")
	// ErrUnknownScheme indica un esquema de firma no soportado.
	ErrUnknownScheme = errors.New("crypto: esquema de firma desconocido")
	// ErrWrongPassphrase indica que la contraseña de un archivo de claves no es correcta.
	ErrWrongPassphrase = errors.New("crypto: contraseña incorrecta o archivo corrupto")
)

// PrivateKey es una clave privada de cualquier esquema soportado.
type PrivateKey interface {
	// Scheme devuelve el esquema de la clave.
	Scheme() KeyType
	// Public devuelve la clave pública asociada.
	Public() PublicKey
	// Sign firma un mensaje arbitrario con la semántica propia del esquema:
	// secp256k1 firma Keccak256(msg) (firma recuperable de 65 bytes),
	// Ed25519 firma msg directamente (64 bytes) y BLS hashea msg a G2 (96 bytes).
	Sign(msg []byte) ([]byte, error)
	// Bytes devuelve la serialización canónica de la clave secreta.
	// Tratar con cuidado: es material secreto.
	Bytes() []byte
}

// PublicKey es una clave pública de cualquier esquema soportado.
type PublicKey interface {
	// Scheme devuelve el esquema de la clave.
	Scheme() KeyType
	// Bytes devuelve la serialización canónica comprimida
	// (33 bytes secp256k1, 32 Ed25519, 48 BLS).
	Bytes() []byte
	// Verify comprueba sig sobre msg con la misma semántica que PrivateKey.Sign.
	Verify(msg, sig []byte) bool
	// Equal informa si ambas claves son idénticas (mismo esquema y bytes).
	Equal(other PublicKey) bool
}

// equalPub es la implementación común de Equal: compara esquema y bytes.
func equalPub(a, b PublicKey) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Scheme() == b.Scheme() && bytes.Equal(a.Bytes(), b.Bytes())
}

// KeyPair agrupa una clave privada con su clave pública ya calculada.
type KeyPair struct {
	// Private es la clave secreta.
	Private PrivateKey
	// Public es la clave pública derivada (cacheada para no recalcularla).
	Public PublicKey
}

// NewKeyPair construye un KeyPair a partir de una clave privada.
func NewKeyPair(priv PrivateKey) *KeyPair {
	return &KeyPair{Private: priv, Public: priv.Public()}
}

// GenerateKey genera una clave nueva del esquema indicado usando r como
// fuente de aleatoriedad (crypto/rand.Reader si r es nil).
func GenerateKey(t KeyType, r io.Reader) (PrivateKey, error) {
	if r == nil {
		r = rand.Reader
	}
	switch t {
	case types.SchemeSecp256k1:
		return GenerateSecp256k1(r)
	case types.SchemeEd25519:
		return GenerateEd25519(r)
	case types.SchemeBLS12381:
		return GenerateBLS(r)
	default:
		return nil, ErrUnknownScheme
	}
}

// GenerateKeyPair genera un KeyPair nuevo del esquema indicado.
func GenerateKeyPair(t KeyType) (*KeyPair, error) {
	priv, err := GenerateKey(t, nil)
	if err != nil {
		return nil, err
	}
	return NewKeyPair(priv), nil
}

// PrivateKeyFromBytes reconstruye una clave privada de su serialización.
func PrivateKeyFromBytes(t KeyType, b []byte) (PrivateKey, error) {
	switch t {
	case types.SchemeSecp256k1:
		return Secp256k1FromBytes(b)
	case types.SchemeEd25519:
		return Ed25519FromSeed(b)
	case types.SchemeBLS12381:
		return BLSPrivateKeyFromBytes(b)
	default:
		return nil, ErrUnknownScheme
	}
}

// PublicKeyFromBytes parsea una clave pública de su serialización.
func PublicKeyFromBytes(t KeyType, b []byte) (PublicKey, error) {
	switch t {
	case types.SchemeSecp256k1:
		return ParseSecp256k1PublicKey(b)
	case types.SchemeEd25519:
		return ParseEd25519PublicKey(b)
	case types.SchemeBLS12381:
		return BLSPublicKeyFromBytes(b)
	default:
		return nil, ErrUnknownScheme
	}
}

// ---------------------------------------------------------------------------
// Archivo de claves cifrado.
// ---------------------------------------------------------------------------

// Parámetros de scrypt. N=2^18, r=8, p=1 es el perfil "estándar" de los
// keystores de Ethereum (~250 ms y 256 MiB por descifrado), suficiente para
// frenar ataques de diccionario offline. Los tests pueden usar LightScryptN.
const (
	StandardScryptN = 1 << 18
	LightScryptN    = 1 << 12
	scryptR         = 8
	scryptP         = 1
	scryptKeyLen    = 32
	keyFileVersion  = 1
)

// EncryptedKey es la representación JSON de un archivo de claves cifrado.
type EncryptedKey struct {
	// Version del formato (actualmente 1).
	Version int `json:"version"`
	// Scheme es el nombre del esquema ("secp256k1", "ed25519", "bls12-381").
	Scheme string `json:"scheme"`
	// PublicKey es la clave pública en hex, en claro, para identificar la clave
	// sin necesidad de la contraseña.
	PublicKey types.HexBytes `json:"publicKey"`
	// Address es la dirección de cuenta (sólo secp256k1).
	Address *types.Address `json:"address,omitempty"`
	// KDF describe la derivación de la clave de cifrado.
	KDF struct {
		N    int            `json:"n"`
		R    int            `json:"r"`
		P    int            `json:"p"`
		Salt types.HexBytes `json:"salt"`
	} `json:"kdf"`
	// Nonce es el nonce de 24 bytes de XChaCha20-Poly1305.
	Nonce types.HexBytes `json:"nonce"`
	// Ciphertext es la clave secreta cifrada + etiqueta de autenticación.
	Ciphertext types.HexBytes `json:"ciphertext"`
}

// schemeFromName traduce el nombre textual de un esquema a KeyType.
func schemeFromName(name string) (KeyType, error) {
	for _, s := range []KeyType{types.SchemeSecp256k1, types.SchemeEd25519, types.SchemeBLS12381} {
		if s.String() == name {
			return s, nil
		}
	}
	return types.SchemeUnknown, ErrUnknownScheme
}

// EncryptKey cifra una clave privada con una contraseña. scryptN controla el
// coste (usar StandardScryptN en producción).
func EncryptKey(priv PrivateKey, passphrase string, scryptN int) (*EncryptedKey, error) {
	ek := &EncryptedKey{Version: keyFileVersion, Scheme: priv.Scheme().String()}
	ek.PublicKey = priv.Public().Bytes()
	if sk, ok := priv.(*Secp256k1PrivateKey); ok {
		a := sk.Address()
		ek.Address = &a
	}
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	dk, err := scrypt.Key([]byte(passphrase), salt, scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(dk)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	// Los datos adicionales autenticados (AAD) atan el cifrado al esquema y a
	// la clave pública: si alguien edita esos campos del JSON, el descifrado falla.
	aad := append([]byte(ek.Scheme), ek.PublicKey...)
	ek.Ciphertext = aead.Seal(nil, nonce, priv.Bytes(), aad)
	ek.Nonce = nonce
	ek.KDF.N, ek.KDF.R, ek.KDF.P, ek.KDF.Salt = scryptN, scryptR, scryptP, salt
	return ek, nil
}

// DecryptKey descifra un EncryptedKey con la contraseña dada y verifica que
// la clave pública resultante coincida con la almacenada.
func DecryptKey(ek *EncryptedKey, passphrase string) (PrivateKey, error) {
	if ek.Version != keyFileVersion {
		return nil, fmt.Errorf("crypto: versión de archivo de claves %d no soportada", ek.Version)
	}
	scheme, err := schemeFromName(ek.Scheme)
	if err != nil {
		return nil, err
	}
	dk, err := scrypt.Key([]byte(passphrase), ek.KDF.Salt, ek.KDF.N, ek.KDF.R, ek.KDF.P, scryptKeyLen)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(dk)
	if err != nil {
		return nil, err
	}
	if len(ek.Nonce) != chacha20poly1305.NonceSizeX {
		return nil, ErrWrongPassphrase
	}
	aad := append([]byte(ek.Scheme), ek.PublicKey...)
	plain, err := aead.Open(nil, ek.Nonce, ek.Ciphertext, aad)
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	priv, err := PrivateKeyFromBytes(scheme, plain)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(priv.Public().Bytes(), ek.PublicKey) {
		return nil, ErrWrongPassphrase
	}
	return priv, nil
}

// SaveKeyFile cifra priv y la guarda en path con permisos 0600. La escritura
// es atómica: se escribe un temporal y se renombra.
func SaveKeyFile(path string, priv PrivateKey, passphrase string, scryptN int) error {
	ek, err := EncryptKey(priv, passphrase, scryptN)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(ek, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LoadKeyFile lee y descifra un archivo de claves.
func LoadKeyFile(path, passphrase string) (PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var ek EncryptedKey
	if err := json.Unmarshal(data, &ek); err != nil {
		return nil, fmt.Errorf("crypto: archivo de claves malformado: %w", err)
	}
	return DecryptKey(&ek, passphrase)
}
