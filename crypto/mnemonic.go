package crypto

// Mnemónicos BIP-39 y derivación jerárquica de claves.
//
//   - BIP-39: entropía (128–256 bits) + checksum SHA-256 → palabras de la
//     lista inglesa oficial (embebida desde bip39_english.txt); semilla de
//     64 bytes = PBKDF2-HMAC-SHA512(mnemónico NFKD, "mnemonic"+frase, 2048).
//   - BIP-32 (secp256k1): derivación de cuentas de usuario con la ruta
//     estándar de Ethereum m/44'/60'/0'/0/i, compatible con wallets.
//   - SLIP-10 (Ed25519): sólo derivación endurecida, para claves de nodo P2P.
//   - BLS: KeyGen IETF aplicado a HKDF(semilla, ruta). Nota: no es EIP-2333
//     (el árbol de claves BLS de Ethereum), pero es determinista y seguro;
//     basta para regenerar claves de validador desde un mnemónico.

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/sha512"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/text/unicode/norm"
)

//go:embed bip39_english.txt
var englishWordsRaw string

// bip39Words es la lista oficial de 2048 palabras y bip39Index su inversa.
var (
	bip39Words []string
	bip39Index map[string]int
)

func init() {
	bip39Words = strings.Fields(englishWordsRaw)
	if len(bip39Words) != 2048 {
		panic("crypto: lista BIP-39 embebida corrupta")
	}
	bip39Index = make(map[string]int, 2048)
	for i, w := range bip39Words {
		bip39Index[w] = i
	}
}

// Errores de mnemónicos y derivación.
var (
	// ErrInvalidEntropy indica una longitud de entropía no permitida.
	ErrInvalidEntropy = errors.New("crypto: entropía debe ser de 128-256 bits, múltiplo de 32")
	// ErrInvalidMnemonic indica palabras desconocidas, número incorrecto o checksum inválido.
	ErrInvalidMnemonic = errors.New("crypto: mnemónico inválido")
	// ErrInvalidPath indica una ruta de derivación malformada.
	ErrInvalidPath = errors.New("crypto: ruta de derivación inválida")
	// ErrDerivation indica un hijo inválido (probabilidad ~2^-127).
	ErrDerivation = errors.New("crypto: derivación produjo una clave inválida")
)

// Rutas de derivación por defecto.
const (
	// DefaultAccountPath es la ruta de Ethereum; %d es el índice de cuenta.
	DefaultAccountPath = "m/44'/60'/0'/0/%d"
	// DefaultNodeKeyPath es la ruta SLIP-10 de la clave de nodo (todo endurecido).
	DefaultNodeKeyPath = "m/44'/7771'/0'/0'/%d'"
	// DefaultValidatorPath es la "ruta" usada como info HKDF para BLS.
	DefaultValidatorPath = "m/12381/7771/0/%d"
	// HardenedOffset marca un índice endurecido (i').
	HardenedOffset = 0x80000000
)

// NewEntropy genera bits de entropía aleatoria (128, 160, 192, 224 o 256).
func NewEntropy(bits int, r io.Reader) ([]byte, error) {
	if bits < 128 || bits > 256 || bits%32 != 0 {
		return nil, ErrInvalidEntropy
	}
	b := make([]byte, bits/8)
	if _, err := io.ReadFull(readerOrDefault(r), b); err != nil {
		return nil, err
	}
	return b, nil
}

// NewMnemonic convierte entropía en un mnemónico. Cada palabra codifica 11
// bits; los últimos bits/32 son el checksum (primeros bits de SHA-256).
func NewMnemonic(entropy []byte) (string, error) {
	bits := len(entropy) * 8
	if bits < 128 || bits > 256 || bits%32 != 0 {
		return "", ErrInvalidEntropy
	}
	csBits := bits / 32
	sum := sha256.Sum256(entropy)
	// Concatenamos entropía || checksum como un entero grande y extraemos
	// grupos de 11 bits desde el más significativo.
	v := new(big.Int).SetBytes(entropy)
	v.Lsh(v, uint(csBits))
	v.Or(v, big.NewInt(int64(sum[0]>>(8-csBits))))
	n := (bits + csBits) / 11
	words := make([]string, n)
	mask := big.NewInt(2047)
	tmp := new(big.Int)
	for i := n - 1; i >= 0; i-- {
		words[i] = bip39Words[tmp.And(v, mask).Int64()]
		v.Rsh(v, 11)
	}
	return strings.Join(words, " "), nil
}

// GenerateMnemonic genera un mnemónico nuevo de bits de entropía (24
// palabras para 256 bits, el recomendado).
func GenerateMnemonic(bits int) (string, error) {
	e, err := NewEntropy(bits, nil)
	if err != nil {
		return "", err
	}
	return NewMnemonic(e)
}

// MnemonicToEntropy valida el mnemónico (palabras y checksum) y devuelve
// la entropía original.
func MnemonicToEntropy(mnemonic string) ([]byte, error) {
	words := strings.Fields(norm.NFKD.String(mnemonic))
	n := len(words)
	if n < 12 || n > 24 || n%3 != 0 {
		return nil, fmt.Errorf("%w: %d palabras", ErrInvalidMnemonic, n)
	}
	v := new(big.Int)
	for _, w := range words {
		idx, ok := bip39Index[w]
		if !ok {
			return nil, fmt.Errorf("%w: palabra desconocida %q", ErrInvalidMnemonic, w)
		}
		v.Lsh(v, 11)
		v.Or(v, big.NewInt(int64(idx)))
	}
	total := n * 11
	csBits := total / 33
	entBits := total - csBits
	cs := new(big.Int).And(v, big.NewInt(int64(1<<csBits-1))).Uint64()
	v.Rsh(v, uint(csBits))
	entropy := v.FillBytes(make([]byte, entBits/8))
	sum := sha256.Sum256(entropy)
	if uint64(sum[0]>>(8-csBits)) != cs {
		return nil, fmt.Errorf("%w: checksum incorrecto", ErrInvalidMnemonic)
	}
	return entropy, nil
}

// ValidateMnemonic informa si el mnemónico es válido.
func ValidateMnemonic(mnemonic string) bool {
	_, err := MnemonicToEntropy(mnemonic)
	return err == nil
}

// MnemonicToSeed deriva la semilla BIP-39 de 64 bytes. La frase opcional
// ("25ª palabra") cambia completamente la semilla. Valida el mnemónico.
func MnemonicToSeed(mnemonic, passphrase string) ([]byte, error) {
	if !ValidateMnemonic(mnemonic) {
		return nil, ErrInvalidMnemonic
	}
	m := strings.Join(strings.Fields(norm.NFKD.String(mnemonic)), " ")
	salt := "mnemonic" + norm.NFKD.String(passphrase)
	return pbkdf2.Key(sha512.New, m, []byte(salt), 2048, 64)
}

// ---------------------------------------------------------------------------
// Rutas de derivación.
// ---------------------------------------------------------------------------

// ParseDerivationPath convierte "m/44'/60'/0'/0/0" en índices uint32 (los
// endurecidos con HardenedOffset sumado). Acepta ' o h como marca.
func ParseDerivationPath(path string) ([]uint32, error) {
	parts := strings.Split(strings.TrimSpace(path), "/")
	if len(parts) == 0 || parts[0] != "m" {
		return nil, fmt.Errorf("%w: %q debe empezar por m/", ErrInvalidPath, path)
	}
	out := make([]uint32, 0, len(parts)-1)
	for _, p := range parts[1:] {
		hardened := strings.HasSuffix(p, "'") || strings.HasSuffix(p, "h")
		p = strings.TrimRight(p, "'h")
		n, err := strconv.ParseUint(p, 10, 31)
		if err != nil {
			return nil, fmt.Errorf("%w: componente %q", ErrInvalidPath, p)
		}
		idx := uint32(n)
		if hardened {
			idx += HardenedOffset
		}
		out = append(out, idx)
	}
	return out, nil
}

// ExtendedKey es una clave extendida BIP-32/SLIP-10: clave + código de cadena.
type ExtendedKey struct {
	// Key es la clave privada de 32 bytes.
	Key [32]byte
	// ChainCode es la entropía adicional para derivar hijos.
	ChainCode [32]byte
	// Depth es la profundidad en el árbol (0 = maestra).
	Depth uint8
	// Index es el índice con el que se derivó (0 para la maestra).
	Index uint32
	// curve distingue secp256k1 (BIP-32) de ed25519 (SLIP-10).
	ed25519 bool
}

// masterKey calcula la clave maestra HMAC-SHA512(curveKey, seed).
func masterKey(seed []byte, curveKey string, ed bool) (*ExtendedKey, error) {
	if len(seed) < 16 || len(seed) > 64 {
		return nil, fmt.Errorf("%w: semilla de %d bytes", ErrInvalidEntropy, len(seed))
	}
	I := HmacSha512([]byte(curveKey), seed)
	k := &ExtendedKey{ed25519: ed}
	copy(k.Key[:], I[:32])
	copy(k.ChainCode[:], I[32:])
	if !ed {
		if _, err := Secp256k1FromBytes(k.Key[:]); err != nil {
			return nil, ErrDerivation
		}
	}
	return k, nil
}

// NewMasterKey crea la clave maestra BIP-32 secp256k1 ("Bitcoin seed").
func NewMasterKey(seed []byte) (*ExtendedKey, error) { return masterKey(seed, "Bitcoin seed", false) }

// NewEd25519MasterKey crea la clave maestra SLIP-10 Ed25519.
func NewEd25519MasterKey(seed []byte) (*ExtendedKey, error) {
	return masterKey(seed, "ed25519 seed", true)
}

// Child deriva el hijo de índice i.
func (k *ExtendedKey) Child(i uint32) (*ExtendedKey, error) {
	var data []byte
	if i >= HardenedOffset {
		// Endurecido: 0x00 || k || ser32(i).
		data = append([]byte{0}, k.Key[:]...)
	} else {
		if k.ed25519 {
			return nil, fmt.Errorf("%w: ed25519 sólo admite índices endurecidos", ErrInvalidPath)
		}
		// Normal: serP(K) || ser32(i) (clave pública comprimida del padre).
		priv, err := Secp256k1FromBytes(k.Key[:])
		if err != nil {
			return nil, err
		}
		data = priv.PublicKey().Bytes()
	}
	data = binary.BigEndian.AppendUint32(data, i)
	I := HmacSha512(k.ChainCode[:], data)
	child := &ExtendedKey{Depth: k.Depth + 1, Index: i, ed25519: k.ed25519}
	copy(child.ChainCode[:], I[32:])
	if k.ed25519 {
		copy(child.Key[:], I[:32]) // SLIP-10 ed25519: IL es la clave directamente
		return child, nil
	}
	// BIP-32: k_hijo = (IL + k_padre) mod n; inválido si IL ≥ n o resultado 0.
	var il, parent secp256k1.ModNScalar
	if il.SetByteSlice(I[:32]) {
		return nil, ErrDerivation
	}
	parent.SetByteSlice(k.Key[:])
	il.Add(&parent)
	if il.IsZero() {
		return nil, ErrDerivation
	}
	child.Key = il.Bytes()
	return child, nil
}

// Derive aplica una ruta completa ("m/..." ) desde esta clave (que debe ser la maestra).
func (k *ExtendedKey) Derive(path string) (*ExtendedKey, error) {
	idxs, err := ParseDerivationPath(path)
	if err != nil {
		return nil, err
	}
	cur := k
	for _, i := range idxs {
		if cur, err = cur.Child(i); err != nil {
			return nil, err
		}
	}
	return cur, nil
}

// Secp256k1 devuelve la clave privada secp256k1 de una clave BIP-32.
func (k *ExtendedKey) Secp256k1() (*Secp256k1PrivateKey, error) {
	if k.ed25519 {
		return nil, ErrUnknownScheme
	}
	return Secp256k1FromBytes(k.Key[:])
}

// Ed25519 devuelve la clave privada Ed25519 de una clave SLIP-10.
func (k *ExtendedKey) Ed25519() (*Ed25519PrivateKey, error) {
	if !k.ed25519 {
		return nil, ErrUnknownScheme
	}
	return Ed25519FromSeed(k.Key[:])
}

// DeriveAccountKey deriva la cuenta de usuario index (m/44'/60'/0'/0/index).
func DeriveAccountKey(seed []byte, index uint32) (*Secp256k1PrivateKey, error) {
	m, err := NewMasterKey(seed)
	if err != nil {
		return nil, err
	}
	k, err := m.Derive(fmt.Sprintf(DefaultAccountPath, index))
	if err != nil {
		return nil, err
	}
	return k.Secp256k1()
}

// DeriveNodeKey deriva la clave de nodo Ed25519 index.
func DeriveNodeKey(seed []byte, index uint32) (*Ed25519PrivateKey, error) {
	m, err := NewEd25519MasterKey(seed)
	if err != nil {
		return nil, err
	}
	k, err := m.Derive(fmt.Sprintf(DefaultNodeKeyPath, index))
	if err != nil {
		return nil, err
	}
	return k.Ed25519()
}

// DeriveValidatorKey deriva la clave BLS de validador index:
// KeyGen(IKM = semilla, key_info = ruta).
func DeriveValidatorKey(seed []byte, index uint32) (*BLSPrivateKey, error) {
	if len(seed) < 32 {
		return nil, ErrInvalidEntropy
	}
	return BLSKeyGen(seed, []byte(fmt.Sprintf(DefaultValidatorPath, index)))
}
