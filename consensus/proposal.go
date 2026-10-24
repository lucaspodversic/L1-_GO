package consensus

// Este archivo define la propuesta: el mensaje con el que el líder de una
// vista difunde su bloque. Contiene:
//
//   - El bloque completo; su campo Justify es el QC que certifica al padre
//     (el highQC del líder) y Header.View es la vista de la propuesta.
//   - Un TC opcional: si el líder entró en la vista por timeout (el QC no es
//     de la vista anterior), debe justificarlo con el TC de view-1.
//   - La prueba VRF cuya salida es Header.Random (la verifica
//     block_validation.go).
//   - La firma BLS del líder sobre (hash del bloque, hash del TC).
//
// La firma de propuesta no forma parte del bloque: una vez comprometido, su
// validez la garantiza el QC del hijo; la firma sólo sirve durante la vista
// para que los votantes sepan que el bloque viene del líder legítimo (y
// para detectar dobles propuestas).

import (
	"errors"
	"fmt"

	"github.com/l1/l1/crypto"
	"github.com/l1/l1/types"
)

// ErrInvalidProposal agrupa los fallos de forma de una propuesta.
var ErrInvalidProposal = errors.New("consenso: propuesta inválida")

// Proposal es la propuesta del líder.
type Proposal struct {
	Block     *types.Block
	TC        *TimeoutCert
	VRFProof  []byte
	Signature []byte
}

// proposalSigningMessage es lo que firma el líder.
func proposalSigningMessage(chainID types.ChainID, blockHash types.Hash, tc *TimeoutCert) []byte {
	var tcHash types.Hash
	if tc != nil {
		tcHash = tc.Hash()
	}
	return crypto.DomainMessage(crypto.DomainProposal, chainID, types.EncodeList(types.EncodeBytes(blockHash[:]), types.EncodeBytes(tcHash[:])))
}

// NewProposal firma una propuesta.
func NewProposal(key *ValidatorKey, chainID types.ChainID, block *types.Block, tc *TimeoutCert, vrfProof []byte) (*Proposal, error) {
	if block == nil {
		return nil, ErrInvalidProposal
	}
	if block.HeaderRef().Proposer != key.Address {
		return nil, fmt.Errorf("%w: el proponente de la cabecera no es la clave local", ErrInvalidProposal)
	}
	sig, err := key.bls.SignBLS(proposalSigningMessage(chainID, block.Hash(), tc))
	if err != nil {
		return nil, err
	}
	return &Proposal{Block: block, TC: tc, VRFProof: vrfProof, Signature: sig.Bytes()}, nil
}

// View es la vista de la propuesta.
func (p *Proposal) View() uint64 { return p.Block.HeaderRef().View }

// Epoch es la época de la propuesta.
func (p *Proposal) Epoch() uint64 { return p.Block.HeaderRef().Epoch }

// Proposer es la dirección del líder.
func (p *Proposal) Proposer() types.Address { return p.Block.HeaderRef().Proposer }

// QC decodifica el QC justificativo del bloque.
func (p *Proposal) QC() (*QuorumCert, error) { return DecodeQuorumCert(p.Block.Justify()) }

// VerifySignature comprueba la firma del líder con su clave.
func (p *Proposal) VerifySignature(pk *crypto.BLSPublicKey, chainID types.ChainID) error {
	sig, err := crypto.BLSSignatureFromBytes(p.Signature)
	if err != nil || pk == nil || !pk.VerifyBLS(proposalSigningMessage(chainID, p.Block.Hash(), p.TC), sig) {
		return ErrInvalidSignature
	}
	return nil
}

// EncodeRLP codifica [bloque, tc | "", vrfProof, firma].
func (p *Proposal) EncodeRLP() []byte {
	tc := types.EncodeBytes(nil)
	if p.TC != nil {
		tc = p.TC.EncodeRLP()
	}
	return types.EncodeList(p.Block.EncodeRLP(), tc, types.EncodeBytes(p.VRFProof), types.EncodeBytes(p.Signature))
}

// DecodeProposal es la inversa de EncodeRLP.
func DecodeProposal(b []byte) (*Proposal, error) {
	it, err := types.DecodeRLP(b)
	if err != nil {
		return nil, err
	}
	f, err := it.ListN(4)
	if err != nil {
		return nil, err
	}
	p := &Proposal{}
	if p.Block, err = types.DecodeBlock(f[0].Raw); err != nil {
		return nil, err
	}
	if f[1].IsList() {
		if p.TC, err = decodeTCItem(f[1]); err != nil {
			return nil, err
		}
	} else if len(f[1].Data) != 0 {
		return nil, fmt.Errorf("%w: TC mal codificado", ErrInvalidProposal)
	}
	if p.VRFProof, err = f[2].BytesCopy(); err != nil {
		return nil, err
	}
	if p.Signature, err = f[3].BytesCopy(); err != nil {
		return nil, err
	}
	return p, nil
}

// ProposalKey identifica (época, vista, proponente) para detectar dobles
// propuestas del mismo líder.
type ProposalKey struct {
	Epoch, View uint64
	Proposer    types.Address
}

// Key devuelve la clave de la propuesta.
func (p *Proposal) Key() ProposalKey {
	return ProposalKey{Epoch: p.Epoch(), View: p.View(), Proposer: p.Proposer()}
}
