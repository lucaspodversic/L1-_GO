package consensus

// Este archivo define los mensajes de timeout y el Timeout Certificate (TC),
// así como la política de duración de los temporizadores.
//
// Cuando un validador no ve progreso en la vista v, firma y difunde un
// TimeoutMsg(v, highQC): "abandono la vista v; el QC más alto que conozco es
// highQC". La firma cubre (época, v, highQC.View). Con 2f+1 de poder de
// timeouts para v se forma un TC, que permite entrar en la vista v+1 sin QC
// de v. Para mantener la seguridad, el líder de v+1 que propone con un TC
// debe extender un QC de vista >= max(highQC.View de los firmantes): así,
// si algún bloque llegó a comprometerse, al menos un honesto del TC tenía
// su QC y el nuevo bloque no puede abandonarlo.
//
// El TC guarda la vista de highQC de cada firmante y UNA firma BLS agregada
// sobre mensajes distintos (crypto.AggregateVerify), además del highQC
// máximo completo para que el siguiente líder pueda extenderlo.

import (
	"errors"
	"fmt"
	"time"

	"github.com/l1/l1/crypto"
	"github.com/l1/l1/types"
)

// Errores de timeouts.
var (
	ErrInvalidTimeout = errors.New("consenso: timeout inválido")
	ErrInvalidTC      = errors.New("consenso: TC inválido")
)

// TimeoutConfig regula la duración de los temporizadores de vista:
// Base · Multiplier^k, con k el número de timeouts consecutivos, acotado
// por Max. El crecimiento exponencial garantiza que, tras GST, la vista
// acaba durando lo suficiente para que un líder honesto progrese.
type TimeoutConfig struct {
	Base       time.Duration
	Multiplier float64
	Max        time.Duration
}

// DefaultTimeoutConfig: 2 s de base, ×1.5 por timeout, máximo 60 s.
func DefaultTimeoutConfig() TimeoutConfig {
	return TimeoutConfig{Base: 2 * time.Second, Multiplier: 1.5, Max: 60 * time.Second}
}

// Duration devuelve la duración tras k timeouts consecutivos.
func (c TimeoutConfig) Duration(k int) time.Duration {
	d := float64(c.Base)
	if d <= 0 {
		d = float64(time.Second)
	}
	m := c.Multiplier
	if m < 1 {
		m = 1
	}
	for i := 0; i < k; i++ {
		d *= m
		if c.Max > 0 && d >= float64(c.Max) {
			return c.Max
		}
	}
	if c.Max > 0 && time.Duration(d) > c.Max {
		return c.Max
	}
	return time.Duration(d)
}

// timeoutSigningMessage es lo que firma un timeout.
func timeoutSigningMessage(chainID types.ChainID, epoch, view, highQCView uint64) []byte {
	payload := types.EncodeList(types.EncodeUint(epoch), types.EncodeUint(view), types.EncodeUint(highQCView))
	return crypto.DomainMessage(crypto.DomainTimeout, chainID, payload)
}

// TimeoutMsg es el timeout firmado de un validador.
type TimeoutMsg struct {
	Epoch  uint64
	View   uint64
	HighQC *QuorumCert
	Sender types.Address
	// Signature firma (Epoch, View, HighQC.View).
	Signature []byte
}

// NewTimeoutMsg firma un timeout para la vista dada.
func NewTimeoutMsg(key *ValidatorKey, chainID types.ChainID, epoch, view uint64, highQC *QuorumCert) (*TimeoutMsg, error) {
	if highQC == nil {
		return nil, fmt.Errorf("%w: sin highQC", ErrInvalidTimeout)
	}
	sig, err := key.bls.SignBLS(timeoutSigningMessage(chainID, epoch, view, highQC.View))
	if err != nil {
		return nil, err
	}
	return &TimeoutMsg{Epoch: epoch, View: view, HighQC: highQC, Sender: key.Address, Signature: sig.Bytes()}, nil
}

// Verify comprueba remitente, firma y el highQC adjunto (con el conjunto de
// su propia época, resuelto mediante sets).
func (t *TimeoutMsg) Verify(set *ValidatorSet, sets ValidatorSetProvider, chainID types.ChainID) error {
	if t.HighQC == nil || t.HighQC.View >= t.View {
		return fmt.Errorf("%w: highQC ausente o no anterior a la vista", ErrInvalidTimeout)
	}
	_, val := set.ByAddress(t.Sender)
	if val == nil {
		return fmt.Errorf("%w: %s", ErrNotValidator, t.Sender.Hex())
	}
	sig, err := crypto.BLSSignatureFromBytes(t.Signature)
	if err != nil || !val.PubKey.VerifyBLS(timeoutSigningMessage(chainID, t.Epoch, t.View, t.HighQC.View), sig) {
		return ErrInvalidSignature
	}
	return verifyQCWith(t.HighQC, sets, chainID)
}

// verifyQCWith verifica un QC con el conjunto de su época.
func verifyQCWith(qc *QuorumCert, sets ValidatorSetProvider, chainID types.ChainID) error {
	if qc.IsGenesis() {
		return nil
	}
	set, err := sets.ValidatorSet(qc.Epoch)
	if err != nil {
		return err
	}
	return qc.Verify(set, chainID)
}

// EncodeRLP codifica [epoch, view, highQC, sender, signature].
func (t *TimeoutMsg) EncodeRLP() []byte {
	return types.EncodeList(types.EncodeUint(t.Epoch), types.EncodeUint(t.View), t.HighQC.EncodeRLP(), types.EncodeBytes(t.Sender[:]), types.EncodeBytes(t.Signature))
}

// DecodeTimeoutMsg es la inversa de EncodeRLP.
func DecodeTimeoutMsg(b []byte) (*TimeoutMsg, error) {
	it, err := types.DecodeRLP(b)
	if err != nil {
		return nil, err
	}
	f, err := it.ListN(5)
	if err != nil {
		return nil, err
	}
	t := &TimeoutMsg{}
	if t.Epoch, err = f[0].Uint64(); err != nil {
		return nil, err
	}
	if t.View, err = f[1].Uint64(); err != nil {
		return nil, err
	}
	if t.HighQC, err = decodeQCItem(f[2]); err != nil {
		return nil, err
	}
	if t.Sender, err = f[3].Address(); err != nil {
		return nil, err
	}
	if t.Signature, err = f[4].BytesCopy(); err != nil {
		return nil, err
	}
	return t, nil
}

// TimeoutCert prueba que 2f+1 de poder abandonó una vista.
type TimeoutCert struct {
	Epoch uint64
	View  uint64
	// Signers marca a los firmantes por índice.
	Signers Bitmap
	// HighQCViews[k] es la vista del highQC del k-ésimo firmante (en orden
	// de índice).
	HighQCViews []uint64
	// HighQC es el QC de vista máxima entre los firmantes.
	HighQC *QuorumCert
	// Signature agrega las firmas de todos los timeouts.
	Signature []byte
}

// MaxHighQCView devuelve max(HighQCViews).
func (tc *TimeoutCert) MaxHighQCView() uint64 {
	var m uint64
	for _, v := range tc.HighQCViews {
		if v > m {
			m = v
		}
	}
	return m
}

// Verify comprueba quórum, firma agregada y coherencia del highQC.
func (tc *TimeoutCert) Verify(set *ValidatorSet, sets ValidatorSetProvider, chainID types.ChainID) error {
	if tc == nil || tc.HighQC == nil {
		return ErrInvalidTC
	}
	power, err := set.PowerOf(tc.Signers)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidTC, err)
	}
	if !set.HasQuorum(power) {
		return fmt.Errorf("%w: %v", ErrInvalidTC, ErrNoQuorum)
	}
	idx := tc.Signers.Indices()
	if len(idx) != len(tc.HighQCViews) {
		return fmt.Errorf("%w: %d vistas para %d firmantes", ErrInvalidTC, len(tc.HighQCViews), len(idx))
	}
	if tc.HighQC.View != tc.MaxHighQCView() {
		return fmt.Errorf("%w: highQC no es el máximo", ErrInvalidTC)
	}
	pks := make([]*crypto.BLSPublicKey, len(idx))
	msgs := make([][]byte, len(idx))
	for k, i := range idx {
		if tc.HighQCViews[k] >= tc.View {
			return fmt.Errorf("%w: highQC posterior a la vista", ErrInvalidTC)
		}
		pks[k] = set.ByIndex(i).PubKey
		msgs[k] = timeoutSigningMessage(chainID, tc.Epoch, tc.View, tc.HighQCViews[k])
	}
	sig, err := crypto.BLSSignatureFromBytes(tc.Signature)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidTC, err)
	}
	if !crypto.AggregateVerify(pks, msgs, sig) {
		return fmt.Errorf("%w: firma agregada", ErrInvalidSignature)
	}
	return verifyQCWith(tc.HighQC, sets, chainID)
}

// Hash identifica el TC.
func (tc *TimeoutCert) Hash() types.Hash { return crypto.Keccak256Hash(tc.EncodeRLP()) }

// EncodeRLP codifica [epoch, view, signers, [vistas], highQC, firma].
func (tc *TimeoutCert) EncodeRLP() []byte {
	views := make([][]byte, len(tc.HighQCViews))
	for i, v := range tc.HighQCViews {
		views[i] = types.EncodeUint(v)
	}
	return types.EncodeList(types.EncodeUint(tc.Epoch), types.EncodeUint(tc.View), tc.Signers.EncodeRLP(),
		types.EncodeList(views...), tc.HighQC.EncodeRLP(), types.EncodeBytes(tc.Signature))
}

// DecodeTimeoutCert es la inversa de EncodeRLP.
func DecodeTimeoutCert(b []byte) (*TimeoutCert, error) {
	it, err := types.DecodeRLP(b)
	if err != nil {
		return nil, err
	}
	return decodeTCItem(it)
}

// decodeTCItem decodifica un TC desde un elemento RLP.
func decodeTCItem(it types.RLPItem) (*TimeoutCert, error) {
	f, err := it.ListN(6)
	if err != nil {
		return nil, err
	}
	tc := &TimeoutCert{}
	if tc.Epoch, err = f[0].Uint64(); err != nil {
		return nil, err
	}
	if tc.View, err = f[1].Uint64(); err != nil {
		return nil, err
	}
	if tc.Signers, err = decodeBitmap(f[2]); err != nil {
		return nil, err
	}
	vs, err := f[3].Items()
	if err != nil {
		return nil, err
	}
	tc.HighQCViews = make([]uint64, len(vs))
	for i, v := range vs {
		if tc.HighQCViews[i], err = v.Uint64(); err != nil {
			return nil, err
		}
	}
	if tc.HighQC, err = decodeQCItem(f[4]); err != nil {
		return nil, err
	}
	if tc.Signature, err = f[5].BytesCopy(); err != nil {
		return nil, err
	}
	return tc, nil
}
