package consensus

// Este archivo define el Quorum Certificate (QC): la prueba de que
// validadores con al menos ⌊2N/3⌋+1 de poder votaron el mismo bloque en la
// misma vista. Gracias a BLS, las firmas individuales se agregan en una
// sola de 96 bytes y el QC sólo necesita además un bitmap de firmantes; la
// verificación es un único FastAggregateVerify (dos pairings).
//
// El QC que certifica al padre viaja codificado en el campo Justify del
// bloque hijo (y Header.JustifyHash lo compromete), de modo que cualquier
// nodo puede comprobar, sólo con la cadena, que cada bloque fue votado.

import (
	"errors"
	"fmt"

	"github.com/l1/l1/crypto"
	"github.com/l1/l1/types"
)

// Errores de QC.
var (
	ErrNoQuorum     = errors.New("consenso: poder insuficiente para quórum")
	ErrInvalidQC    = errors.New("consenso: QC inválido")
	ErrQCMismatch   = errors.New("consenso: el QC no certifica al padre")
	ErrEmptyJustify = errors.New("consenso: bloque sin justificación")
)

// VoteData es el contenido firmado por un voto (y certificado por un QC).
type VoteData struct {
	Epoch       uint64
	View        uint64
	BlockNumber uint64
	BlockHash   types.Hash
}

// encode codifica VoteData en RLP.
func (d VoteData) encode() []byte {
	return types.EncodeList(types.EncodeUint(d.Epoch), types.EncodeUint(d.View), types.EncodeUint(d.BlockNumber), types.EncodeBytes(d.BlockHash[:]))
}

// SigningMessage es el mensaje con dominio que se firma para votar.
func (d VoteData) SigningMessage(chainID types.ChainID) []byte {
	return crypto.DomainMessage(crypto.DomainVote, chainID, d.encode())
}

// QuorumCert certifica un bloque.
type QuorumCert struct {
	VoteData
	// Signers marca, por índice del conjunto de la época, quién firmó.
	Signers Bitmap
	// Signature es la firma BLS agregada (vacía en el QC génesis).
	Signature []byte
}

// GenesisQC es el QC sintético que "certifica" al bloque génesis: vista 0,
// sin firmas. Sólo es aceptable para el bloque de altura 0.
func GenesisQC(genesis *types.Header) *QuorumCert {
	return &QuorumCert{VoteData: VoteData{Epoch: genesis.Epoch, View: genesis.View, BlockNumber: 0, BlockHash: genesis.Hash()}}
}

// IsGenesis informa si es el QC sintético del génesis.
func (qc *QuorumCert) IsGenesis() bool { return qc.BlockNumber == 0 && len(qc.Signature) == 0 }

// Verify comprueba el QC contra el conjunto de validadores de su época.
// El QC génesis se acepta sin firmas (el llamante debe comprobar que su
// BlockHash es el del génesis conocido).
func (qc *QuorumCert) Verify(set *ValidatorSet, chainID types.ChainID) error {
	if qc == nil {
		return ErrInvalidQC
	}
	if qc.IsGenesis() {
		return nil
	}
	power, err := set.PowerOf(qc.Signers)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidQC, err)
	}
	if !set.HasQuorum(power) {
		return fmt.Errorf("%w: %d < %d", ErrNoQuorum, power, set.QuorumPower())
	}
	pks, _ := set.PubKeysOf(qc.Signers)
	sig, err := crypto.BLSSignatureFromBytes(qc.Signature)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidQC, err)
	}
	if !crypto.FastAggregateVerify(pks, qc.SigningMessage(chainID), sig) {
		return fmt.Errorf("%w: firma agregada", ErrInvalidSignature)
	}
	return nil
}

// Hash identifica el QC (Keccak256 de su codificación); coincide con
// Header.JustifyHash del bloque que lo incluye.
func (qc *QuorumCert) Hash() types.Hash { return types.JustifyHash(qc.EncodeRLP()) }

// EncodeRLP codifica [voteData, signers, signature].
func (qc *QuorumCert) EncodeRLP() []byte {
	bm := qc.Signers
	if bm.bits == nil {
		bm = NewBitmap(0)
	}
	return types.EncodeList(qc.VoteData.encode(), bm.EncodeRLP(), types.EncodeBytes(qc.Signature))
}

// DecodeQuorumCert decodifica un QC (p. ej. Block.Justify()).
func DecodeQuorumCert(b []byte) (*QuorumCert, error) {
	if len(b) == 0 {
		return nil, ErrEmptyJustify
	}
	it, err := types.DecodeRLP(b)
	if err != nil {
		return nil, err
	}
	return decodeQCItem(it)
}

// decodeQCItem decodifica un QC desde un elemento RLP ya separado.
func decodeQCItem(it types.RLPItem) (*QuorumCert, error) {
	f, err := it.ListN(3)
	if err != nil {
		return nil, err
	}
	vd, err := decodeVoteData(f[0])
	if err != nil {
		return nil, err
	}
	bm, err := decodeBitmap(f[1])
	if err != nil {
		return nil, err
	}
	sig, err := f[2].BytesCopy()
	if err != nil {
		return nil, err
	}
	if len(sig) != 0 && len(sig) != 96 {
		return nil, fmt.Errorf("%w: firma de %d bytes", ErrInvalidQC, len(sig))
	}
	return &QuorumCert{VoteData: vd, Signers: bm, Signature: sig}, nil
}

// decodeVoteData decodifica [epoch, view, number, hash].
func decodeVoteData(it types.RLPItem) (VoteData, error) {
	f, err := it.ListN(4)
	if err != nil {
		return VoteData{}, err
	}
	var d VoteData
	if d.Epoch, err = f[0].Uint64(); err != nil {
		return d, err
	}
	if d.View, err = f[1].Uint64(); err != nil {
		return d, err
	}
	if d.BlockNumber, err = f[2].Uint64(); err != nil {
		return d, err
	}
	d.BlockHash, err = f[3].Hash()
	return d, err
}

// AggregateVotes construye un QC a partir de votos ya verificados sobre los
// mismos datos. Devuelve ErrNoQuorum si no alcanzan el umbral.
func AggregateVotes(set *ValidatorSet, votes []*Vote) (*QuorumCert, error) {
	if len(votes) == 0 {
		return nil, ErrNoQuorum
	}
	data := votes[0].VoteData
	bm := NewBitmap(set.Size())
	sigs := make([]*crypto.BLSSignature, 0, len(votes))
	var power uint64
	for _, v := range votes {
		if v.VoteData != data {
			return nil, fmt.Errorf("%w: votos sobre datos distintos", ErrInvalidQC)
		}
		i, val := set.ByAddress(v.Voter)
		if val == nil {
			return nil, ErrNotValidator
		}
		if bm.Get(i) {
			continue // duplicado del mismo votante
		}
		s, err := crypto.BLSSignatureFromBytes(v.Signature)
		if err != nil {
			return nil, err
		}
		bm.Set(i)
		sigs = append(sigs, s)
		power += val.Power
	}
	if !set.HasQuorum(power) {
		return nil, ErrNoQuorum
	}
	agg, err := crypto.AggregateSignatures(sigs)
	if err != nil {
		return nil, err
	}
	return &QuorumCert{VoteData: data, Signers: bm, Signature: agg.Bytes()}, nil
}

// String resume el QC.
func (qc *QuorumCert) String() string {
	return fmt.Sprintf("QC{epoch=%d view=%d #%d %s firmantes=%d}", qc.Epoch, qc.View, qc.BlockNumber, qc.BlockHash.Hex(), qc.Signers.Count())
}
