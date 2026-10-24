package consensus

// Este archivo define el voto de un validador sobre una propuesta y el
// colector de votos que usa el líder de la vista siguiente para formar el
// QC. El colector también detecta equivocaciones (dos votos del mismo
// validador en la misma vista para bloques distintos) y produce la
// evidencia que permite penalizarlas (slashing.go).

import (
	"errors"
	"fmt"
	"sync"

	"github.com/l1/l1/crypto"
	"github.com/l1/l1/types"
)

// Errores de votos.
var (
	ErrDuplicateVote = errors.New("consenso: voto duplicado")
	ErrWrongEpoch    = errors.New("consenso: época incorrecta")
)

// Vote es el voto firmado de un validador.
type Vote struct {
	VoteData
	// Voter es la dirección del validador.
	Voter types.Address
	// Signature es la firma BLS (96 bytes) de VoteData.SigningMessage.
	Signature []byte
}

// NewVote firma un voto con la clave local.
func NewVote(key *ValidatorKey, chainID types.ChainID, data VoteData) (*Vote, error) {
	sig, err := key.bls.SignBLS(data.SigningMessage(chainID))
	if err != nil {
		return nil, err
	}
	return &Vote{VoteData: data, Voter: key.Address, Signature: sig.Bytes()}, nil
}

// Verify comprueba que el votante pertenece al conjunto y la firma.
func (v *Vote) Verify(set *ValidatorSet, chainID types.ChainID) error {
	_, val := set.ByAddress(v.Voter)
	if val == nil {
		return fmt.Errorf("%w: %s", ErrNotValidator, v.Voter.Hex())
	}
	return v.VerifyWithKey(val.PubKey, chainID)
}

// VerifyWithKey verifica la firma con una clave pública concreta (la usa la
// verificación de evidencias, que toma la clave del estado de staking).
func (v *Vote) VerifyWithKey(pk *crypto.BLSPublicKey, chainID types.ChainID) error {
	if pk == nil {
		return ErrInvalidSignature
	}
	sig, err := crypto.BLSSignatureFromBytes(v.Signature)
	if err != nil || !pk.VerifyBLS(v.SigningMessage(chainID), sig) {
		return ErrInvalidSignature
	}
	return nil
}

// EncodeRLP codifica [voteData, voter, signature].
func (v *Vote) EncodeRLP() []byte {
	return types.EncodeList(v.VoteData.encode(), types.EncodeBytes(v.Voter[:]), types.EncodeBytes(v.Signature))
}

// DecodeVote es la inversa de EncodeRLP.
func DecodeVote(b []byte) (*Vote, error) {
	it, err := types.DecodeRLP(b)
	if err != nil {
		return nil, err
	}
	return decodeVoteItem(it)
}

// decodeVoteItem decodifica un voto desde un elemento RLP.
func decodeVoteItem(it types.RLPItem) (*Vote, error) {
	f, err := it.ListN(3)
	if err != nil {
		return nil, err
	}
	vd, err := decodeVoteData(f[0])
	if err != nil {
		return nil, err
	}
	addr, err := f[1].Address()
	if err != nil {
		return nil, err
	}
	sig, err := f[2].BytesCopy()
	if err != nil {
		return nil, err
	}
	return &Vote{VoteData: vd, Voter: addr, Signature: sig}, nil
}

// voterView identifica (vista, votante) para detectar equivocaciones.
type voterView struct {
	view  uint64
	voter types.Address
}

// voteBucket acumula los votos sobre unos mismos VoteData.
type voteBucket struct {
	votes []*Vote
	power uint64
	qc    *QuorumCert // formado al alcanzar quórum
}

// VoteCollector agrupa votos por VoteData hasta alcanzar quórum. Es seguro
// para uso concurrente. Verifica cada voto al recibirlo (así un voto con
// firma inválida no puede envenenar la agregación).
type VoteCollector struct {
	mu      sync.Mutex
	chainID types.ChainID
	epoch   uint64
	set     *ValidatorSet
	buckets map[VoteData]*voteBucket
	byVoter map[voterView]*Vote
}

// NewVoteCollector crea un colector para el conjunto de una época.
func NewVoteCollector(chainID types.ChainID, epoch uint64, set *ValidatorSet) *VoteCollector {
	return &VoteCollector{
		chainID: chainID, epoch: epoch, set: set,
		buckets: make(map[VoteData]*voteBucket),
		byVoter: make(map[voterView]*Vote),
	}
}

// AddVote incorpora un voto. Devuelve el QC la PRIMERA vez que su bloque
// alcanza quórum (nil en el resto de casos) y, si el voto contradice uno
// anterior del mismo validador en la misma vista, la evidencia de doble
// voto (el voto contradictorio no se cuenta).
func (c *VoteCollector) AddVote(v *Vote) (*QuorumCert, *DoubleVoteEvidence, error) {
	if v.Epoch != c.epoch {
		return nil, nil, fmt.Errorf("%w: %d != %d", ErrWrongEpoch, v.Epoch, c.epoch)
	}
	if err := v.Verify(c.set, c.chainID); err != nil {
		return nil, nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	key := voterView{v.View, v.Voter}
	if prev, ok := c.byVoter[key]; ok {
		if prev.VoteData == v.VoteData {
			return nil, nil, ErrDuplicateVote
		}
		return nil, &DoubleVoteEvidence{A: prev, B: v}, nil
	}
	c.byVoter[key] = v
	b := c.buckets[v.VoteData]
	if b == nil {
		b = &voteBucket{}
		c.buckets[v.VoteData] = b
	}
	_, val := c.set.ByAddress(v.Voter)
	b.votes = append(b.votes, v)
	b.power += val.Power
	if b.qc == nil && c.set.HasQuorum(b.power) {
		qc, err := AggregateVotes(c.set, b.votes)
		if err != nil {
			return nil, nil, err
		}
		b.qc = qc
		return qc, nil, nil
	}
	return nil, nil, nil
}

// Power devuelve el poder acumulado para unos VoteData.
func (c *VoteCollector) Power(d VoteData) uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if b := c.buckets[d]; b != nil {
		return b.power
	}
	return 0
}

// Prune descarta todo lo de vistas inferiores a minView.
func (c *VoteCollector) Prune(minView uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for d := range c.buckets {
		if d.View < minView {
			delete(c.buckets, d)
		}
	}
	for k := range c.byVoter {
		if k.view < minView {
			delete(c.byVoter, k)
		}
	}
}
