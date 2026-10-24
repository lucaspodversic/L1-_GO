package crypto

// BLS12-381 es el esquema de firma del consenso. Su propiedad clave es la
// agregación: n firmas de validadores sobre el mismo voto se combinan en UNA
// firma de 96 bytes verificable con una sola comprobación de pairing contra
// la suma de sus claves públicas. Eso hace que los Quorum Certificates de
// HotStuff tengan tamaño constante.
//
// Variante elegida (igual que Ethereum consensus layer / IETF
// draft-irtf-cfrg-bls-signature, ciphersuite "POP"):
//   - Claves públicas en G1 (48 bytes comprimidas), firmas en G2 (96 bytes).
//   - Hash a curva: hash_to_curve SSWU con expand_message_xmd SHA-256.
//   - Protección contra ataques de clave maliciosa (rogue-key) mediante
//     Proof-of-Possession: cada validador firma su propia clave pública con
//     un DST distinto al registrarse. Por eso FastAggregateVerify es seguro.
//
// La verificación usa la identidad e(pk, H(m)) == e(g1, σ), que se comprueba
// como e(pk, H(m)) · e(-g1, σ) == 1 en un solo PairingCheck (un solo
// exponenciado final, más barato que dos pairings independientes).

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/l1/l1/types"
)

// Tamaños de serialización BLS.
const (
	BLSSecretKeySize = 32
	BLSPublicKeySize = bls12381.SizeOfG1AffineCompressed // 48
	BLSSignatureSize = bls12381.SizeOfG2AffineCompressed // 96
)

// Domain Separation Tags del ciphersuite POP del draft IETF.
var (
	// DSTSignature se usa para firmar mensajes ordinarios (votos, propuestas).
	DSTSignature = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_")
	// DSTProofOfPossession se usa sólo para las pruebas de posesión.
	DSTProofOfPossession = []byte("BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_")
)

// ErrBLSEmptyAggregate se devuelve al agregar una lista vacía.
var ErrBLSEmptyAggregate = errors.New("crypto: agregación BLS de lista vacía")

// g1Gen, g1GenNeg son el generador de G1 y su opuesto (cacheados).
var g1Gen, g1GenNeg bls12381.G1Affine

func init() {
	_, _, g1Gen, _ = bls12381.Generators()
	g1GenNeg.Neg(&g1Gen)
}

// BLSPrivateKey es un escalar secreto en [1, r-1], r = orden de los subgrupos.
type BLSPrivateKey struct {
	sk *big.Int
}

// BLSPublicKey es un punto de G1: pk = sk · g1.
type BLSPublicKey struct {
	p bls12381.G1Affine
}

// BLSSignature es un punto de G2: σ = sk · H(m).
type BLSSignature struct {
	p bls12381.G2Affine
}

// ---------------------------------------------------------------------------
// Generación y serialización de claves.
// ---------------------------------------------------------------------------

// GenerateBLS genera una clave nueva leyendo 32 bytes de entropía de r y
// aplicando KeyGen.
func GenerateBLS(r io.Reader) (*BLSPrivateKey, error) {
	if r == nil {
		r = rand.Reader
	}
	ikm := make([]byte, 32)
	if _, err := io.ReadFull(r, ikm); err != nil {
		return nil, err
	}
	return BLSKeyGen(ikm, nil)
}

// BLSKeyGen implementa KeyGen del draft IETF (sección 2.3): deriva una clave
// determinista de un material de entrada (≥32 bytes) con HKDF-SHA256,
// re-hasheando la sal hasta obtener un escalar no nulo. keyInfo es opcional.
func BLSKeyGen(ikm, keyInfo []byte) (*BLSPrivateKey, error) {
	if len(ikm) < 32 {
		return nil, fmt.Errorf("%w: IKM BLS de %d bytes (<32)", ErrInvalidPrivateKey, len(ikm))
	}
	const L = 48 // ceil((3 * ceil(log2(r))) / 16)
	salt := []byte("BLS-SIG-KEYGEN-SALT-")
	r := fr.Modulus()
	for {
		s := sha256.Sum256(salt)
		salt = s[:]
		prk, err := hkdf.Extract(sha256.New, append(append([]byte{}, ikm...), 0), salt)
		if err != nil {
			return nil, err
		}
		info := string(append(append([]byte{}, keyInfo...), byte(L>>8), byte(L)))
		okm, err := hkdf.Expand(sha256.New, prk, info, L)
		if err != nil {
			return nil, err
		}
		sk := new(big.Int).SetBytes(okm)
		sk.Mod(sk, r)
		if sk.Sign() != 0 {
			return &BLSPrivateKey{sk: sk}, nil
		}
	}
}

// BLSPrivateKeyFromBytes parsea un escalar de 32 bytes big-endian; rechaza
// 0 y valores ≥ r.
func BLSPrivateKeyFromBytes(b []byte) (*BLSPrivateKey, error) {
	if len(b) != BLSSecretKeySize {
		return nil, fmt.Errorf("%w: BLS de %d bytes", ErrInvalidPrivateKey, len(b))
	}
	sk := new(big.Int).SetBytes(b)
	if sk.Sign() == 0 || sk.Cmp(fr.Modulus()) >= 0 {
		return nil, ErrInvalidPrivateKey
	}
	return &BLSPrivateKey{sk: sk}, nil
}

// BLSPublicKeyFromBytes parsea una clave pública comprimida de 48 bytes,
// comprobando que esté en el subgrupo y que no sea el punto en el infinito
// (KeyValidate del draft).
func BLSPublicKeyFromBytes(b []byte) (*BLSPublicKey, error) {
	if len(b) != BLSPublicKeySize {
		return nil, fmt.Errorf("%w: BLS de %d bytes", ErrInvalidPublicKey, len(b))
	}
	var pk BLSPublicKey
	// SetBytes verifica pertenencia a la curva y al subgrupo.
	if _, err := pk.p.SetBytes(b); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPublicKey, err)
	}
	if pk.p.IsInfinity() {
		return nil, fmt.Errorf("%w: punto en el infinito", ErrInvalidPublicKey)
	}
	return &pk, nil
}

// BLSSignatureFromBytes parsea una firma comprimida de 96 bytes, con
// comprobación de subgrupo.
func BLSSignatureFromBytes(b []byte) (*BLSSignature, error) {
	if len(b) != BLSSignatureSize {
		return nil, fmt.Errorf("%w: firma BLS de %d bytes", types.ErrInvalidSignature, len(b))
	}
	var s BLSSignature
	if _, err := s.p.SetBytes(b); err != nil {
		return nil, fmt.Errorf("%w: %v", types.ErrInvalidSignature, err)
	}
	return &s, nil
}

// Scheme implementa PrivateKey.
func (k *BLSPrivateKey) Scheme() KeyType { return types.SchemeBLS12381 }

// Public implementa PrivateKey.
func (k *BLSPrivateKey) Public() PublicKey { return k.PublicKey() }

// PublicKey devuelve pk = sk·g1 con su tipo concreto.
func (k *BLSPrivateKey) PublicKey() *BLSPublicKey {
	var pk BLSPublicKey
	pk.p.ScalarMultiplicationBase(k.sk)
	return &pk
}

// Bytes implementa PrivateKey: 32 bytes big-endian.
func (k *BLSPrivateKey) Bytes() []byte {
	out := make([]byte, BLSSecretKeySize)
	k.sk.FillBytes(out)
	return out
}

// Sign implementa PrivateKey con el DST de firmas ordinarias.
func (k *BLSPrivateKey) Sign(msg []byte) ([]byte, error) {
	s, err := k.SignDST(msg, DSTSignature)
	if err != nil {
		return nil, err
	}
	return s.Bytes(), nil
}

// SignBLS firma msg y devuelve la firma con su tipo concreto.
func (k *BLSPrivateKey) SignBLS(msg []byte) (*BLSSignature, error) {
	return k.SignDST(msg, DSTSignature)
}

// SignDST firma msg con un DST arbitrario: σ = sk · HashToG2(msg, dst).
func (k *BLSPrivateKey) SignDST(msg, dst []byte) (*BLSSignature, error) {
	h, err := bls12381.HashToG2(msg, dst)
	if err != nil {
		return nil, err
	}
	var s BLSSignature
	s.p.ScalarMultiplication(&h, k.sk)
	return &s, nil
}

// ProvePossession genera la Proof-of-Possession: firma de la propia clave
// pública serializada con DSTProofOfPossession.
func (k *BLSPrivateKey) ProvePossession() (*BLSSignature, error) {
	return k.SignDST(k.PublicKey().Bytes(), DSTProofOfPossession)
}

// Scheme implementa PublicKey.
func (pk *BLSPublicKey) Scheme() KeyType { return types.SchemeBLS12381 }

// Bytes implementa PublicKey: 48 bytes comprimidos.
func (pk *BLSPublicKey) Bytes() []byte { b := pk.p.Bytes(); return b[:] }

// Verify implementa PublicKey con el DST de firmas ordinarias.
func (pk *BLSPublicKey) Verify(msg, sig []byte) bool {
	s, err := BLSSignatureFromBytes(sig)
	if err != nil {
		return false
	}
	return pk.VerifyDST(msg, s, DSTSignature)
}

// VerifyBLS verifica una firma ya parseada sobre msg.
func (pk *BLSPublicKey) VerifyBLS(msg []byte, sig *BLSSignature) bool {
	return pk.VerifyDST(msg, sig, DSTSignature)
}

// VerifyDST comprueba e(pk, H(m)) · e(-g1, σ) == 1.
func (pk *BLSPublicKey) VerifyDST(msg []byte, sig *BLSSignature, dst []byte) bool {
	if pk == nil || sig == nil || pk.p.IsInfinity() {
		return false
	}
	h, err := bls12381.HashToG2(msg, dst)
	if err != nil {
		return false
	}
	ok, err := bls12381.PairingCheck(
		[]bls12381.G1Affine{pk.p, g1GenNeg},
		[]bls12381.G2Affine{h, sig.p},
	)
	return err == nil && ok
}

// VerifyPossession verifica una Proof-of-Possession.
func (pk *BLSPublicKey) VerifyPossession(pop *BLSSignature) bool {
	return pk.VerifyDST(pk.Bytes(), pop, DSTProofOfPossession)
}

// Equal implementa PublicKey.
func (pk *BLSPublicKey) Equal(o PublicKey) bool { return equalPub(pk, o) }

// Bytes devuelve la firma comprimida de 96 bytes.
func (s *BLSSignature) Bytes() []byte { b := s.p.Bytes(); return b[:] }

// Equal informa si dos firmas son el mismo punto.
func (s *BLSSignature) Equal(o *BLSSignature) bool { return o != nil && s.p.Equal(&o.p) }

// ---------------------------------------------------------------------------
// Agregación.
// ---------------------------------------------------------------------------

// AggregateSignatures suma firmas en G2. El resultado verifica contra la
// suma de las claves públicas correspondientes (si firmaron el mismo mensaje).
func AggregateSignatures(sigs []*BLSSignature) (*BLSSignature, error) {
	if len(sigs) == 0 {
		return nil, ErrBLSEmptyAggregate
	}
	var acc bls12381.G2Jac
	acc.FromAffine(&sigs[0].p)
	for _, s := range sigs[1:] {
		acc.AddMixed(&s.p)
	}
	var out BLSSignature
	out.p.FromJacobian(&acc)
	return &out, nil
}

// AggregatePublicKeys suma claves públicas en G1.
func AggregatePublicKeys(pks []*BLSPublicKey) (*BLSPublicKey, error) {
	if len(pks) == 0 {
		return nil, ErrBLSEmptyAggregate
	}
	var acc bls12381.G1Jac
	acc.FromAffine(&pks[0].p)
	for _, p := range pks[1:] {
		acc.AddMixed(&p.p)
	}
	var out BLSPublicKey
	out.p.FromJacobian(&acc)
	return &out, nil
}

// FastAggregateVerify verifica una firma agregada de varios firmantes sobre
// el MISMO mensaje. Sólo es seguro si todas las claves tienen PoP verificada
// (lo garantiza el registro de validadores).
func FastAggregateVerify(pks []*BLSPublicKey, msg []byte, sig *BLSSignature) bool {
	agg, err := AggregatePublicKeys(pks)
	if err != nil {
		return false
	}
	return agg.VerifyBLS(msg, sig)
}

// AggregateVerify verifica una firma agregada sobre mensajes potencialmente
// distintos: ∏ e(pk_i, H(m_i)) · e(-g1, σ) == 1. Usado p. ej. para agregar
// votos de timeout con distintas vistas "high QC".
func AggregateVerify(pks []*BLSPublicKey, msgs [][]byte, sig *BLSSignature) bool {
	if len(pks) == 0 || len(pks) != len(msgs) || sig == nil {
		return false
	}
	g1s := make([]bls12381.G1Affine, 0, len(pks)+1)
	g2s := make([]bls12381.G2Affine, 0, len(pks)+1)
	for i, pk := range pks {
		if pk == nil || pk.p.IsInfinity() {
			return false
		}
		h, err := bls12381.HashToG2(msgs[i], DSTSignature)
		if err != nil {
			return false
		}
		g1s = append(g1s, pk.p)
		g2s = append(g2s, h)
	}
	g1s = append(g1s, g1GenNeg)
	g2s = append(g2s, sig.p)
	ok, err := bls12381.PairingCheck(g1s, g2s)
	return err == nil && ok
}

// blsBatchVerify verifica n firmas individuales (pk_i, m_i, σ_i) con una sola
// comprobación de pairing usando coeficientes aleatorios r_i de 64 bits:
// ∏ e(r_i·pk_i, H(m_i)) · e(-g1, Σ r_i·σ_i) == 1. Un atacante no puede
// hacer que firmas inválidas se cancelen porque no conoce los r_i.
// Si devuelve false, al menos una firma es inválida.
func blsBatchVerify(pks []*BLSPublicKey, msgs [][]byte, sigs []*BLSSignature) bool {
	n := len(pks)
	if n == 0 || n != len(msgs) || n != len(sigs) {
		return false
	}
	g1s := make([]bls12381.G1Affine, 0, n+1)
	g2s := make([]bls12381.G2Affine, 0, n+1)
	var sigAcc bls12381.G2Jac
	var buf [8]byte
	for i := 0; i < n; i++ {
		if pks[i] == nil || sigs[i] == nil || pks[i].p.IsInfinity() {
			return false
		}
		if _, err := io.ReadFull(rand.Reader, buf[:]); err != nil {
			return false
		}
		r := new(big.Int).SetBytes(buf[:])
		r.SetBit(r, 0, 1) // nunca cero
		h, err := bls12381.HashToG2(msgs[i], DSTSignature)
		if err != nil {
			return false
		}
		var pkr bls12381.G1Affine
		pkr.ScalarMultiplication(&pks[i].p, r)
		var sr bls12381.G2Affine
		sr.ScalarMultiplication(&sigs[i].p, r)
		g1s = append(g1s, pkr)
		g2s = append(g2s, h)
		sigAcc.AddMixed(&sr)
	}
	var sigSum bls12381.G2Affine
	sigSum.FromJacobian(&sigAcc)
	g1s = append(g1s, g1GenNeg)
	g2s = append(g2s, sigSum)
	ok, err := bls12381.PairingCheck(g1s, g2s)
	return err == nil && ok
}
