package consensus

// Este archivo gestiona la identidad criptográfica de un validador local:
// su dirección de cuenta (con la que se registró en staking) y su clave
// privada BLS, con la que firma propuestas, votos y timeouts bajo
// separación de dominio (crypto.DomainMessage) y produce la prueba VRF de
// aleatoriedad. Incluye persistencia cifrada en disco.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/l1/l1/crypto"
	"github.com/l1/l1/types"
)

// ValidatorKey es la identidad de firma de un validador.
type ValidatorKey struct {
	// Address es la cuenta del validador.
	Address types.Address
	// bls es la clave privada de consenso (nunca se exporta salvo cifrada).
	bls *crypto.BLSPrivateKey
}

// NewValidatorKey envuelve una clave BLS existente.
func NewValidatorKey(addr types.Address, sk *crypto.BLSPrivateKey) (*ValidatorKey, error) {
	if sk == nil {
		return nil, errors.New("consenso: clave BLS nula")
	}
	return &ValidatorKey{Address: addr, bls: sk}, nil
}

// GenerateValidatorKey crea una clave BLS nueva para addr (rand nil usa la
// fuente segura del sistema).
func GenerateValidatorKey(addr types.Address, rand io.Reader) (*ValidatorKey, error) {
	sk, err := crypto.GenerateBLS(rand)
	if err != nil {
		return nil, err
	}
	return NewValidatorKey(addr, sk)
}

// PublicKey devuelve la clave pública BLS.
func (k *ValidatorKey) PublicKey() *crypto.BLSPublicKey { return k.bls.PublicKey() }

// Validator construye la entrada de conjunto correspondiente con un poder.
func (k *ValidatorKey) Validator(power uint64) *Validator {
	return &Validator{Address: k.Address, PubKey: k.PublicKey(), Power: power}
}

// SignDomain firma msg bajo un dominio y chain ID.
func (k *ValidatorKey) SignDomain(domain string, chainID types.ChainID, msg []byte) ([]byte, error) {
	sig, err := k.bls.SignBLS(crypto.DomainMessage(domain, chainID, msg))
	if err != nil {
		return nil, err
	}
	return sig.Bytes(), nil
}

// ProvePossession produce la prueba de posesión que exige el registro en
// staking (protege contra ataques de clave maliciosa en la agregación).
func (k *ValidatorKey) ProvePossession() ([]byte, error) {
	pop, err := k.bls.ProvePossession()
	if err != nil {
		return nil, err
	}
	return pop.Bytes(), nil
}

// VRFProve evalúa la VRF sobre la entrada canónica de (época, vista) y
// devuelve la salida (que va en Header.Random) y la prueba.
func (k *ValidatorKey) VRFProve(chainID types.ChainID, epoch, view uint64, prevRandom types.Hash) (types.Hash, []byte, error) {
	return crypto.VRFProve(k.bls, crypto.VRFInput(chainID, epoch, view, prevRandom))
}

// VerifyDomainSig verifica una firma BLS (en bytes) bajo un dominio.
func VerifyDomainSig(pk *crypto.BLSPublicKey, domain string, chainID types.ChainID, msg, sig []byte) bool {
	if pk == nil {
		return false
	}
	s, err := crypto.BLSSignatureFromBytes(sig)
	if err != nil {
		return false
	}
	return pk.VerifyBLS(crypto.DomainMessage(domain, chainID, msg), s)
}

// validatorKeyFile es el formato JSON en disco.
type validatorKeyFile struct {
	Address types.Address        `json:"address"`
	Key     *crypto.EncryptedKey `json:"key"`
}

// SaveValidatorKey escribe la clave cifrada con passphrase (scryptN regula
// el coste del KDF) en path con permisos 0600, de forma atómica.
func SaveValidatorKey(path string, k *ValidatorKey, passphrase string, scryptN int) error {
	ek, err := crypto.EncryptKey(k.bls, passphrase, scryptN)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(validatorKeyFile{Address: k.Address, Key: ek}, "", "  ")
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

// LoadValidatorKey lee y descifra una clave guardada con SaveValidatorKey.
func LoadValidatorKey(path, passphrase string) (*ValidatorKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f validatorKeyFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("consenso: archivo de clave inválido: %w", err)
	}
	if f.Key == nil {
		return nil, errors.New("consenso: archivo de clave sin clave")
	}
	priv, err := crypto.DecryptKey(f.Key, passphrase)
	if err != nil {
		return nil, err
	}
	sk, ok := priv.(*crypto.BLSPrivateKey)
	if !ok {
		return nil, errors.New("consenso: la clave no es BLS")
	}
	return NewValidatorKey(f.Address, sk)
}
