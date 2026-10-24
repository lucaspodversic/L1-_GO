package consensus

// Este archivo implementa la emisión y reparto de recompensas por bloque.
// Además de las propinas (que la ejecución ya paga al coinbase), cada
// bloque acuña BlockReward nuevos tokens que se reparten así:
//
//   - ProposerBonusBps (por defecto 10 %) para el proponente del bloque.
//   - El resto entre los FIRMANTES del QC incluido en el bloque (que
//     certifican al padre), proporcionalmente a su poder de voto. Esto
//     premia la participación y, de paso, incentiva al líder a incluir el
//     QC más completo posible.
//   - Los restos de las divisiones enteras se asignan al proponente, de modo
//     que lo acuñado es exactamente BlockReward.
//
// Las recompensas se abonan directamente al saldo de la cuenta del
// validador (no se re-vinculan automáticamente como stake). El reparto se
// ejecuta dentro de execution.Finalizer, antes de calcular la raíz de
// estado, así que forma parte del consenso sobre el estado.

import (
	"fmt"

	"github.com/l1/l1/execution"
	"github.com/l1/l1/storage"
	"github.com/l1/l1/types"
)

// basisPoints es el denominador de los porcentajes en puntos básicos.
const basisPoints = 10_000

// RewardParams parametriza la emisión.
type RewardParams struct {
	// BlockReward es lo acuñado por bloque.
	BlockReward types.Amount
	// ProposerBonusBps es la parte del proponente en puntos básicos.
	ProposerBonusBps uint64
}

// DefaultRewardParams: 2 tokens por bloque, 10 % para el proponente.
func DefaultRewardParams() RewardParams {
	return RewardParams{BlockReward: types.EtherAmount(2), ProposerBonusBps: 1000}
}

// RewardSummary detalla un reparto (útil para métricas y pruebas).
type RewardSummary struct {
	Minted   types.Amount
	Proposer types.Amount
	Voters   map[types.Address]types.Amount
}

// BalanceAdder es lo mínimo que necesita el reparto del estado.
type BalanceAdder interface {
	AddBalance(types.Address, types.Amount)
}

// DistributeBlockReward reparte la recompensa de un bloque. qc es el QC
// incluido en el bloque y set el conjunto de SU época (la del padre). Con
// el QC génesis (o nil) todo va al proponente.
func DistributeBlockReward(st BalanceAdder, proposer types.Address, qc *QuorumCert, set *ValidatorSet, p RewardParams) (RewardSummary, error) {
	sum := RewardSummary{Minted: p.BlockReward, Voters: map[types.Address]types.Amount{}}
	if p.BlockReward.IsZero() {
		return sum, nil
	}
	bonus := p.BlockReward.MulUint64(p.ProposerBonusBps).DivUint64(basisPoints)
	pool := p.BlockReward.Sub(bonus)
	proposerTotal := bonus
	if qc == nil || qc.IsGenesis() || set == nil {
		proposerTotal = p.BlockReward
	} else {
		signed, err := set.PowerOf(qc.Signers)
		if err != nil {
			return sum, err
		}
		if signed == 0 {
			proposerTotal = p.BlockReward
		} else {
			distributed := types.Amount{}
			for _, i := range qc.Signers.Indices() {
				v := set.ByIndex(i)
				share := pool.MulUint64(v.Power).DivUint64(signed)
				if share.IsZero() {
					continue
				}
				st.AddBalance(v.Address, share)
				sum.Voters[v.Address] = share
				distributed = distributed.Add(share)
			}
			proposerTotal = proposerTotal.Add(pool.Sub(distributed))
		}
	}
	if !proposerTotal.IsZero() {
		st.AddBalance(proposer, proposerTotal)
	}
	sum.Proposer = proposerTotal
	return sum, nil
}

// RewardFinalizer implementa execution.Finalizer aplicando el reparto de
// recompensas de cada bloque.
type RewardFinalizer struct {
	Params RewardParams
	// Sets resuelve el conjunto de validadores de la época del QC.
	Sets ValidatorSetProvider
	// OnReward, si no es nil, recibe el resumen de cada bloque.
	OnReward func(header *types.Header, s RewardSummary)
}

// Finalize implementa execution.Finalizer.
func (f *RewardFinalizer) Finalize(_ *execution.EVM, header *types.Header, justify []byte, statedb *storage.StateDB, _ types.Transactions, _ types.Receipts) error {
	if header.Number == 0 {
		return nil
	}
	var (
		qc  *QuorumCert
		set *ValidatorSet
		err error
	)
	if len(justify) > 0 {
		if qc, err = DecodeQuorumCert(justify); err != nil {
			return fmt.Errorf("recompensas: justify inválido: %w", err)
		}
		if !qc.IsGenesis() && f.Sets != nil {
			if set, err = f.Sets.ValidatorSet(qc.Epoch); err != nil {
				return fmt.Errorf("recompensas: %w", err)
			}
		}
	}
	s, err := DistributeBlockReward(statedb, header.Proposer, qc, set, f.Params)
	if err != nil {
		return err
	}
	if f.OnReward != nil {
		f.OnReward(header, s)
	}
	return nil
}
