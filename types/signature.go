package types

// Este archivo define los tipos de firma que viajan dentro de estructuras del
// protocolo. Aquí sólo hay representación y validación de rango; la
// criptografía real (firmar, verificar, recuperar) está en el paquete crypto.
//
// Hay dos familias:
//
//   - Signature: firma secp256k1 RECUPERABLE de 65 bytes (R || S || V) usada
//     por las transacciones de usuarios. "Recuperable" significa que a partir
//     de la firma y el mensaje se obtiene la clave pública, así que la
//     transacción no necesita incluir el remitente: se deriva.
//   - SchemeSignature: firma etiquetada con su esquema (secp256k1, ed25519 o
//     BLS), útil para mensajes de consenso y P2P donde conviven varios tipos.

import (
	"fmt"
	"math/big"
)

// secp256k1N es el orden del grupo de la curva secp256k1.
var secp256k1N, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)

// secp256k1HalfN es N/2: las firmas con S > N/2 se rechazan (EIP-2) porque
// (R, N-S) también es válida y permitiría maleabilidad del hash de la tx.
var secp256k1HalfN = new(big.Int).Rsh(secp256k1N, 1)

// Signature es una firma secp256k1 recuperable: R(32) || S(32) || V(1), con
// V ∈ {0, 1} (el "recovery id" o paridad de Y). La codificación de la
// transacción traduce V al formato EIP-155 o y_parity según el tipo.
type Signature [SignatureLength]byte

// NewSignature arma una firma a partir de sus componentes.
func NewSignature(r, s *big.Int, v byte) (Signature, error) {
	var sig Signature
	if r == nil || s == nil || r.Sign() < 0 || s.Sign() < 0 || r.BitLen() > 256 || s.BitLen() > 256 {
		return sig, ErrInvalidSignature
	}
	r.FillBytes(sig[0:32])
	s.FillBytes(sig[32:64])
	sig[64] = v
	return sig, nil
}

// SignatureFromBytes copia 65 bytes en una Signature.
func SignatureFromBytes(b []byte) (Signature, error) {
	var sig Signature
	if len(b) != SignatureLength {
		return sig, fmt.Errorf("%w: firma de %d bytes", ErrInvalidLength, len(b))
	}
	copy(sig[:], b)
	return sig, nil
}

// R devuelve la componente R como entero.
func (s Signature) R() *big.Int { return new(big.Int).SetBytes(s[0:32]) }

// S devuelve la componente S como entero.
func (s Signature) S() *big.Int { return new(big.Int).SetBytes(s[32:64]) }

// V devuelve el recovery id (0 o 1).
func (s Signature) V() byte { return s[64] }

// IsZero informa si la firma está vacía (transacción sin firmar).
func (s Signature) IsZero() bool { return s == Signature{} }

// Bytes devuelve una copia de los 65 bytes.
func (s Signature) Bytes() []byte { return append([]byte(nil), s[:]...) }

// Hex devuelve la firma en hexadecimal.
func (s Signature) Hex() string { return EncodeHex(s[:]) }

// ValidateValues comprueba que R y S estén en [1, N-1], que V sea 0 o 1 y,
// si homestead es true, que S esté en la mitad baja (EIP-2, anti-maleabilidad).
// Todas las transacciones de esta cadena se validan con homestead = true.
func (s Signature) ValidateValues(homestead bool) bool {
	if s.V() > 1 {
		return false
	}
	r, sv := s.R(), s.S()
	if r.Sign() <= 0 || sv.Sign() <= 0 {
		return false
	}
	if homestead && sv.Cmp(secp256k1HalfN) > 0 {
		return false
	}
	return r.Cmp(secp256k1N) < 0 && sv.Cmp(secp256k1N) < 0
}

// MarshalText implementa encoding.TextMarshaler.
func (s Signature) MarshalText() ([]byte, error) { return []byte(s.Hex()), nil }

// UnmarshalText implementa encoding.TextUnmarshaler.
func (s *Signature) UnmarshalText(text []byte) error {
	b, err := DecodeHex(string(text))
	if err != nil {
		return err
	}
	v, err := SignatureFromBytes(b)
	if err != nil {
		return err
	}
	*s = v
	return nil
}

// SigScheme identifica un esquema de firma.
type SigScheme uint8

const (
	// SchemeUnknown es el valor por defecto (inválido).
	SchemeUnknown SigScheme = iota
	// SchemeSecp256k1: ECDSA sobre secp256k1 (cuentas de usuario).
	SchemeSecp256k1
	// SchemeEd25519: EdDSA sobre Curve25519 (identidad de nodos P2P).
	SchemeEd25519
	// SchemeBLS12381: BLS sobre BLS12-381 (votos de validadores, agregables).
	SchemeBLS12381
)

// String devuelve el nombre legible del esquema.
func (s SigScheme) String() string {
	switch s {
	case SchemeSecp256k1:
		return "secp256k1"
	case SchemeEd25519:
		return "ed25519"
	case SchemeBLS12381:
		return "bls12-381"
	default:
		return fmt.Sprintf("desconocido(%d)", uint8(s))
	}
}

// SignatureSize devuelve el tamaño esperado de una firma del esquema
// (0 si es desconocido).
func (s SigScheme) SignatureSize() int {
	switch s {
	case SchemeSecp256k1:
		return SignatureLength // 65, recuperable
	case SchemeEd25519:
		return 64
	case SchemeBLS12381:
		return 96 // punto comprimido de G2
	default:
		return 0
	}
}

// PublicKeySize devuelve el tamaño de la clave pública serializada.
func (s SigScheme) PublicKeySize() int {
	switch s {
	case SchemeSecp256k1:
		return 33 // comprimida
	case SchemeEd25519:
		return 32
	case SchemeBLS12381:
		return 48 // punto comprimido de G1
	default:
		return 0
	}
}

// SchemeSignature es una firma acompañada de su esquema.
type SchemeSignature struct {
	// Scheme indica cómo interpretar Bytes.
	Scheme SigScheme
	// Bytes es la firma serializada según el esquema.
	Bytes []byte
}

// Validate comprueba que el tamaño coincida con el esquema.
func (s SchemeSignature) Validate() error {
	want := s.Scheme.SignatureSize()
	if want == 0 {
		return fmt.Errorf("%w: esquema %s", ErrInvalidSignature, s.Scheme)
	}
	if len(s.Bytes) != want {
		return fmt.Errorf("%w: %s requiere %d bytes, hay %d", ErrInvalidSignature, s.Scheme, want, len(s.Bytes))
	}
	return nil
}

// EncodeRLP codifica como lista [scheme, bytes].
func (s SchemeSignature) EncodeRLP() []byte {
	return EncodeList(EncodeUint(uint64(s.Scheme)), EncodeBytes(s.Bytes))
}

// DecodeSchemeSignature decodifica desde un ítem RLP y valida el tamaño.
func DecodeSchemeSignature(it RLPItem) (SchemeSignature, error) {
	l, err := it.ListN(2)
	if err != nil {
		return SchemeSignature{}, err
	}
	sc, err := l[0].Uint64()
	if err != nil {
		return SchemeSignature{}, err
	}
	b, err := l[1].BytesCopy()
	if err != nil {
		return SchemeSignature{}, err
	}
	out := SchemeSignature{Scheme: SigScheme(sc), Bytes: b}
	return out, out.Validate()
}
