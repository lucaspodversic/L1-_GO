package consensus

// Este archivo implementa el slashing por equivocación (doble voto): si un
// validador firma dos votos distintos para la misma (época, vista), viola la
// regla de seguridad que hace imposible certificar dos bloques en
// conflicto. Cualquiera que observe ambos votos puede enviar la evidencia
// al contrato de sistema de evidencias (0x…1100) con una transacción
// normal; el contrato:
//
//  1. Comprueba que los votos son del mismo validador, misma época y vista,
//     y datos distintos; y que ambas firmas BLS son válidas con la clave
//     registrada en staking (no hace falta el conjunto de la época).
//  2. Rechaza evidencia ya procesada (marca su ID en almacenamiento) o
//     demasiado antigua (más de MaxEvidenceAgeEpochs).
//  3. Penaliza DoubleSignSlashBps del stake (execution.SlashValidator, que
//     también alcanza lo que esté en desvinculación), lo encarcela
//     JailEpochs épocas y paga ReporterRewardBps de lo penalizado al
//     denunciante; el resto se quema.
//
// Ser un contrato de sistema hace que la penalización sea parte de la
// ejecución determinista del bloque, sin campos especiales en la cabecera.

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/l1/l1/crypto"
	"github.com/l1/l1/execution"
	"github.com/l1/l1/types"
)

// EvidenceContractAddress es la dirección del contrato de evidencias.
var EvidenceContractAddress = types.Address{18: 0x11}

// Errores de evidencia.
var (
	ErrInvalidEvidence   = errors.New("consenso: evidencia inválida")
	ErrEvidenceProcessed = errors.New("consenso: evidencia ya procesada")
	ErrEvidenceTooOld    = errors.New("consenso: evidencia demasiado antigua")
)

// EventValidatorSlashed es el topic del evento Slashed(address,uint256,address).
var EventValidatorSlashed = crypto.Keccak256Hash([]byte("ValidatorSlashed(address,uint256,address)"))

// SlashingParams parametriza las penalizaciones.
type SlashingParams struct {
	DoubleSignSlashBps   uint64
	JailEpochs           uint64
	ReporterRewardBps    uint64
	MaxEvidenceAgeEpochs uint64
}

// DefaultSlashingParams: 5 % del stake, 4 épocas de cárcel, 10 % para el
// denunciante y evidencia válida durante 2 épocas (el periodo de
// desvinculación, para que no se pueda escapar retirando el stake).
func DefaultSlashingParams() SlashingParams {
	return SlashingParams{DoubleSignSlashBps: 500, JailEpochs: 4, ReporterRewardBps: 1000, MaxEvidenceAgeEpochs: 2}
}

// DoubleVoteEvidence son dos votos contradictorios del mismo validador.
type DoubleVoteEvidence struct {
	A, B *Vote
}

// Offender es el validador infractor.
func (e *DoubleVoteEvidence) Offender() types.Address { return e.A.Voter }

// ValidateBasic comprueba la forma de la evidencia sin criptografía.
func (e *DoubleVoteEvidence) ValidateBasic() error {
	if e == nil || e.A == nil || e.B == nil {
		return ErrInvalidEvidence
	}
	switch {
	case e.A.Voter != e.B.Voter:
		return fmt.Errorf("%w: votantes distintos", ErrInvalidEvidence)
	case e.A.Epoch != e.B.Epoch || e.A.View != e.B.View:
		return fmt.Errorf("%w: vistas distintas", ErrInvalidEvidence)
	case e.A.VoteData == e.B.VoteData:
		return fmt.Errorf("%w: votos idénticos", ErrInvalidEvidence)
	}
	return nil
}

// Verify comprueba forma y ambas firmas con la clave del infractor.
func (e *DoubleVoteEvidence) Verify(pk *crypto.BLSPublicKey, chainID types.ChainID) error {
	if err := e.ValidateBasic(); err != nil {
		return err
	}
	if err := e.A.VerifyWithKey(pk, chainID); err != nil {
		return fmt.Errorf("%w: voto A: %v", ErrInvalidEvidence, err)
	}
	if err := e.B.VerifyWithKey(pk, chainID); err != nil {
		return fmt.Errorf("%w: voto B: %v", ErrInvalidEvidence, err)
	}
	return nil
}

// canonical devuelve los dos votos codificados en orden lexicográfico, para
// que (A,B) y (B,A) tengan el mismo ID.
func (e *DoubleVoteEvidence) canonical() ([]byte, []byte) {
	a, b := e.A.EncodeRLP(), e.B.EncodeRLP()
	if bytes.Compare(a, b) > 0 {
		a, b = b, a
	}
	return a, b
}

// ID identifica la evidencia independientemente del orden de los votos.
// Nota: se calcula sobre VoteData + votante (no sobre las firmas) para que
// no se pueda "reenviar" la misma infracción con firmas re-aleatorizadas.
func (e *DoubleVoteEvidence) ID() types.Hash {
	a := types.EncodeList(e.A.VoteData.encode(), types.EncodeBytes(e.A.Voter[:]))
	b := types.EncodeList(e.B.VoteData.encode(), types.EncodeBytes(e.B.Voter[:]))
	if bytes.Compare(a, b) > 0 {
		a, b = b, a
	}
	return crypto.Keccak256Hash([]byte("l1/evidence/double-vote"), a, b)
}

// EncodeRLP codifica [votoA, votoB] en orden canónico.
func (e *DoubleVoteEvidence) EncodeRLP() []byte {
	a, b := e.canonical()
	return types.EncodeList(a, b)
}

// DecodeDoubleVoteEvidence es la inversa de EncodeRLP.
func DecodeDoubleVoteEvidence(b []byte) (*DoubleVoteEvidence, error) {
	it, err := types.DecodeRLP(b)
	if err != nil {
		return nil, err
	}
	f, err := it.ListN(2)
	if err != nil {
		return nil, err
	}
	a, err := decodeVoteItem(f[0])
	if err != nil {
		return nil, err
	}
	c, err := decodeVoteItem(f[1])
	if err != nil {
		return nil, err
	}
	return &DoubleVoteEvidence{A: a, B: c}, nil
}

// ---------------------------------------------------------------------------
// Contrato de evidencias
// ---------------------------------------------------------------------------

// Selectores del contrato.
var (
	selSubmitDoubleVote = execution.Selector("submitDoubleVote(bytes)")
	selIsProcessed      = execution.Selector("isProcessed(bytes32)")
)

// Gas fijo: dos verificaciones BLS (~2 pairings cada una) más estado.
const (
	gasSubmitEvidence = 200_000
	gasIsProcessed    = 2_600
)

// SlashingContract implementa execution.SystemContract.
type SlashingContract struct {
	params  SlashingParams
	chainID types.ChainID
}

// NewSlashingContract crea el contrato.
func NewSlashingContract(chainID types.ChainID, p SlashingParams) *SlashingContract {
	return &SlashingContract{params: p, chainID: chainID}
}

// RegisterSlashingContract añade el contrato a la configuración de cadena.
func RegisterSlashingContract(cfg *execution.ChainConfig, p SlashingParams) {
	if cfg.SystemContracts == nil {
		cfg.SystemContracts = map[types.Address]execution.SystemContract{}
	}
	cfg.SystemContracts[EvidenceContractAddress] = NewSlashingContract(cfg.ChainID, p)
}

// RequiredGas implementa SystemContract.
func (c *SlashingContract) RequiredGas(input []byte) uint64 {
	if len(input) >= 4 && bytes.Equal(input[:4], selIsProcessed[:]) {
		return gasIsProcessed
	}
	return gasSubmitEvidence
}

// SlashResult resume una penalización aplicada.
type SlashResult struct {
	Offender types.Address
	Slashed  types.Amount
	Reporter types.Amount
	JailedTo uint64
}

// ApplyDoubleVote verifica y aplica la evidencia sobre el estado (también
// la usan pruebas y herramientas fuera de la EVM). epoch es la época actual.
func ApplyDoubleVote(st execution.StakingWriter, chainID types.ChainID, p SlashingParams, ev *DoubleVoteEvidence, epoch uint64, reporter types.Address) (*SlashResult, error) {
	if err := ev.ValidateBasic(); err != nil {
		return nil, err
	}
	if ev.A.Epoch+p.MaxEvidenceAgeEpochs < epoch {
		return nil, ErrEvidenceTooOld
	}
	id := ev.ID()
	if st.GetState(EvidenceContractAddress, id) != (types.Hash{}) {
		return nil, ErrEvidenceProcessed
	}
	pk, rec, err := ValidatorPubKey(st, ev.Offender())
	if err != nil {
		return nil, err
	}
	if err := ev.Verify(pk, chainID); err != nil {
		return nil, err
	}
	amount := rec.Stake.Add(rec.Unbonding).MulUint64(p.DoubleSignSlashBps).DivUint64(basisPoints)
	slashed := execution.SlashValidator(st, ev.Offender(), amount)
	jailTo := epoch + p.JailEpochs
	execution.JailValidator(st, ev.Offender(), jailTo)
	reward := slashed.MulUint64(p.ReporterRewardBps).DivUint64(basisPoints)
	if !reward.IsZero() && reporter != (types.Address{}) {
		st.AddBalance(reporter, reward)
	}
	// Marca la evidencia como procesada y evita que la cuenta del contrato
	// se considere vacía (EIP-161) y pierda su almacenamiento.
	if st.GetNonce(EvidenceContractAddress) == 0 {
		st.SetNonce(EvidenceContractAddress, 1)
	}
	st.SetState(EvidenceContractAddress, id, types.Hash{31: 1})
	return &SlashResult{Offender: ev.Offender(), Slashed: slashed, Reporter: reward, JailedTo: jailTo}, nil
}

// Run implementa SystemContract.
func (c *SlashingContract) Run(ctx *execution.SystemCallContext, input []byte) ([]byte, error) {
	if len(input) < 4 {
		return execution.EncodeRevertReason("evidencias: sin selector"), execution.ErrExecutionReverted
	}
	if ctx.Value != nil && !ctx.Value.IsZero() {
		return execution.EncodeRevertReason("evidencias: no payable"), execution.ErrExecutionReverted
	}
	var sel [4]byte
	copy(sel[:], input)
	args := input[4:]
	db := ctx.EVM.StateDB
	switch sel {
	case selIsProcessed:
		vals, err := execution.DecodeABI([]string{"bytes32"}, args)
		if err != nil {
			return execution.EncodeRevertReason("evidencias: argumentos inválidos"), execution.ErrExecutionReverted
		}
		id := types.BytesToHash(vals[0].([]byte))
		return execution.EncodeABI([]string{"bool"}, []any{db.GetState(EvidenceContractAddress, id) != (types.Hash{})})
	case selSubmitDoubleVote:
		if ctx.ReadOnly {
			return nil, execution.ErrWriteProtection
		}
		vals, err := execution.DecodeABI([]string{"bytes"}, args)
		if err != nil {
			return execution.EncodeRevertReason("evidencias: argumentos inválidos"), execution.ErrExecutionReverted
		}
		ev, err := DecodeDoubleVoteEvidence(vals[0].([]byte))
		if err != nil {
			return execution.EncodeRevertReason("evidencias: codificación inválida"), execution.ErrExecutionReverted
		}
		res, err := ApplyDoubleVote(db, c.chainID, c.params, ev, ctx.EVM.Context.Epoch, ctx.Caller)
		if err != nil {
			return execution.EncodeRevertReason(err.Error()), execution.ErrExecutionReverted
		}
		data, _ := execution.EncodeABI([]string{"uint256", "address"}, []any{res.Slashed, ctx.Caller})
		execution.EmitLog(ctx.EVM, ctx.Self, []types.Hash{EventValidatorSlashed, types.BytesToHash(res.Offender[:])}, data)
		return nil, nil
	}
	return execution.EncodeRevertReason("evidencias: selector desconocido"), execution.ErrExecutionReverted
}
