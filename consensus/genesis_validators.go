package consensus

// Conversión entre types.GenesisValidator (especificación JSON) y el
// ValidatorSet de consenso, más instalación en el estado de staking.

import (
	"fmt"

	"github.com/l1/l1/crypto"
	"github.com/l1/l1/execution"
	"github.com/l1/l1/types"
)

// ValidatorSetFromGenesis construye el conjunto a partir de la lista del
// génesis. Verifica PoP si está presente.
func ValidatorSetFromGenesis(vals []types.GenesisValidator) (*ValidatorSet, error) {
	out := make([]*Validator, 0, len(vals))
	for i, v := range vals {
		pk, err := crypto.BLSPublicKeyFromBytes(v.BLSPubKey)
		if err != nil {
			return nil, fmt.Errorf("consenso: validador génesis %d: clave: %w", i, err)
		}
		if len(v.ProofOfPossession) > 0 {
			sig, err := crypto.BLSSignatureFromBytes(v.ProofOfPossession)
			if err != nil {
				return nil, fmt.Errorf("consenso: validador génesis %d: pop: %w", i, err)
			}
			if !pk.VerifyPossession(sig) {
				return nil, fmt.Errorf("consenso: validador génesis %d: pop inválido", i)
			}
		}
		out = append(out, &Validator{Address: v.Address, PubKey: pk, Power: v.Power})
	}
	return NewValidatorSet(out)
}

// InstallFromGenesis escribe las fichas de staking del génesis en el estado.
func InstallFromGenesis(st execution.StakingWriter, g *types.Genesis) error {
	if g == nil {
		return fmt.Errorf("consenso: génesis nulo")
	}
	vals := make([]GenesisValidator, 0, len(g.Validators))
	for _, v := range g.Validators {
		pk, err := crypto.BLSPublicKeyFromBytes(v.BLSPubKey)
		if err != nil {
			return err
		}
		stake := types.EtherAmount(1)
		if !g.Consensus.MinStake.IsZero() {
			stake = g.Consensus.MinStake
		}
		// El poder del génesis se interpreta como múltiplos de MinStake si
		// Power > 0; se acredita Power * MinStake como stake.
		if v.Power > 1 {
			stake = stake.MulUint64(v.Power)
		}
		vals = append(vals, GenesisValidator{Address: v.Address, BLSKey: pk, Stake: stake})
	}
	return InstallGenesisValidators(st, vals)
}

// GenesisValidatorKeyFile convierte una ValidatorKey al formato génesis.
func GenesisValidatorFromKey(k *ValidatorKey, power uint64) (types.GenesisValidator, error) {
	pop, err := k.ProvePossession()
	if err != nil {
		return types.GenesisValidator{}, err
	}
	return types.GenesisValidator{
		Address:           k.Address,
		BLSPubKey:         k.PublicKey().Bytes(),
		ProofOfPossession: pop,
		Power:             power,
	}, nil
}
