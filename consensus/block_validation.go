package consensus

// Este archivo valida bloques y propuestas completos (salvo la ejecución de
// transacciones, que hace execution.BlockProcessor):
//
// ValidateBlock (bloques ya comprometidos, p. ej. al sincronizar):
//  1. Cabecera con su época (header_validation.go).
//  2. Cuerpo: TxRoot y JustifyHash coinciden con lo recibido.
//  3. Justify: QC que certifica exactamente al padre (hash, altura, vista y
//     época) con firmas válidas del conjunto de la época del padre. El
//     primer bloque lleva el QC sintético del génesis.
//  4. El proponente es el líder de la vista.
//
// ValidateProposal (propuestas en vivo) añade:
//  5. La vista está justificada: QC de view-1, o TC válido de view-1.
//  6. La firma del líder sobre la propuesta.
//  7. La prueba VRF: VRFVerify(clave del líder, α(época, vista, Random del
//     padre)) = Header.Random. Así la aleatoriedad no es manipulable por el
//     líder (sólo puede elegir no proponer).

import (
	"errors"
	"fmt"

	"github.com/l1/l1/crypto"
	"github.com/l1/l1/storage"
	"github.com/l1/l1/types"
)

// ErrInvalidBlock agrupa los fallos de bloque.
var ErrInvalidBlock = errors.New("consenso: bloque inválido")

// ErrWrongLeader indica que el proponente no es el líder de la vista.
var ErrWrongLeader = errors.New("consenso: el proponente no es el líder de la vista")

// BlockValidator valida bloques y propuestas.
type BlockValidator struct {
	Headers     *HeaderValidator
	Epochs      *EpochManager
	Elector     LeaderElector
	GenesisHash types.Hash
}

// NewBlockValidator crea el validador.
func NewBlockValidator(headers *HeaderValidator, epochs *EpochManager, elector LeaderElector, genesis types.Hash) *BlockValidator {
	if elector == nil {
		elector = WeightedElector{}
	}
	return &BlockValidator{Headers: headers, Epochs: epochs, Elector: elector, GenesisHash: genesis}
}

// ValidateBlock aplica las reglas 1-4 y devuelve el QC justificativo.
func (v *BlockValidator) ValidateBlock(block *types.Block, parent *types.Header) (*QuorumCert, error) {
	header := block.HeaderRef()
	info, err := v.Epochs.Get(header.Epoch)
	if err != nil {
		return nil, err
	}
	if err := v.Headers.VerifyHeaderWithEpoch(header, parent, info); err != nil {
		return nil, err
	}
	if err := block.ValidateBody(storage.NewListHasher()); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidBlock, err)
	}
	qc, err := DecodeQuorumCert(block.Justify())
	if err != nil {
		return nil, fmt.Errorf("%w: justify: %v", ErrInvalidBlock, err)
	}
	if err := v.checkJustify(qc, parent); err != nil {
		return nil, err
	}
	if !IsLeader(v.Elector, info, header.View, header.Proposer) {
		return nil, fmt.Errorf("%w: vista %d, proponente %s", ErrWrongLeader, header.View, header.Proposer.Hex())
	}
	return qc, nil
}

// checkJustify comprueba que qc certifica al padre y es válido.
func (v *BlockValidator) checkJustify(qc *QuorumCert, parent *types.Header) error {
	if qc.BlockHash != parent.Hash() || qc.BlockNumber != parent.Number || qc.View != parent.View || qc.Epoch != parent.Epoch {
		return fmt.Errorf("%w: %s", ErrQCMismatch, qc)
	}
	if qc.IsGenesis() {
		if parent.Number != 0 || parent.Hash() != v.GenesisHash {
			return fmt.Errorf("%w: QC génesis sobre un bloque que no es el génesis", ErrInvalidQC)
		}
		return nil
	}
	set, err := v.Epochs.ValidatorSet(qc.Epoch)
	if err != nil {
		return err
	}
	return qc.Verify(set, v.Headers.ChainID)
}

// ValidateProposal aplica las reglas 1-7 y devuelve el QC justificativo.
func (v *BlockValidator) ValidateProposal(p *Proposal, parent *types.Header) (*QuorumCert, error) {
	qc, err := v.ValidateBlock(p.Block, parent)
	if err != nil {
		return nil, err
	}
	header := p.Block.HeaderRef()
	view := header.View
	chainID := v.Headers.ChainID
	switch {
	case qc.View+1 == view:
		// Camino feliz; un TC adjunto sería superfluo pero se verifica si
		// viene (para no aceptar basura firmada).
		if p.TC != nil {
			if err := v.verifyTC(p.TC); err != nil {
				return nil, err
			}
		}
	case p.TC != nil && p.TC.View+1 == view:
		if err := v.verifyTC(p.TC); err != nil {
			return nil, err
		}
		// Tras un timeout el líder debe extender el QC más alto que
		// reporta el TC (si no, podría abandonar un bloque comprometido).
		if qc.View < p.TC.MaxHighQCView() {
			return nil, fmt.Errorf("%w: QC de vista %d por debajo del highQC %d del TC", ErrInvalidProposal, qc.View, p.TC.MaxHighQCView())
		}
	default:
		return nil, fmt.Errorf("%w: vista %d sin QC ni TC de la vista anterior", ErrInvalidProposal, view)
	}
	info, _ := v.Epochs.Get(header.Epoch)
	_, leader := info.Validators.ByAddress(header.Proposer)
	if err := p.VerifySignature(leader.PubKey, chainID); err != nil {
		return nil, err
	}
	beta, ok := crypto.VRFVerify(leader.PubKey, crypto.VRFInput(chainID, header.Epoch, view, parent.Random), p.VRFProof)
	if !ok || beta != header.Random {
		return nil, fmt.Errorf("%w: prueba VRF inválida", ErrInvalidProposal)
	}
	return qc, nil
}

// verifyTC verifica un TC con el conjunto de su época.
func (v *BlockValidator) verifyTC(tc *TimeoutCert) error {
	set, err := v.Epochs.ValidatorSet(tc.Epoch)
	if err != nil {
		return err
	}
	return tc.Verify(set, v.Epochs, v.Headers.ChainID)
}
