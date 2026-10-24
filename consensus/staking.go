package consensus

// Este archivo es la vista del consenso sobre el contrato de staking nativo
// (execution/system_contracts.go). El contrato guarda en el estado las
// fichas de los validadores (stake, estado, clave BLS, cárcel...); aquí se
// traduce ese estado a un ValidatorSet:
//
//  1. Se descartan los no activos (encarcelados, retirados) y los que no
//     alcanzan el stake mínimo o tienen una clave BLS inválida.
//  2. Se ordenan por stake descendente (desempate por dirección) y se toman
//     como mucho MaxValidators.
//  3. El poder de voto es stake / PowerUnit (por defecto 1 gwei), lo que
//     cabe holgadamente en uint64 para cualquier suministro realista.
//
// Como el cálculo sólo depende del estado comprometido, todos los nodos
// obtienen exactamente el mismo conjunto para la época siguiente.

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/l1/l1/crypto"
	"github.com/l1/l1/execution"
	"github.com/l1/l1/types"
)

// StakingParams parametriza la selección de validadores.
type StakingParams struct {
	// MinStake es el stake mínimo para entrar en el conjunto.
	MinStake types.Amount
	// MaxValidators acota el tamaño del conjunto (0 = sin límite).
	MaxValidators int
	// PowerUnit es el divisor stake→poder.
	PowerUnit types.Amount
}

// DefaultStakingParams: mínimo de 1 ether, 100 validadores, poder en gwei.
func DefaultStakingParams() StakingParams {
	return StakingParams{MinStake: types.EtherAmount(1), MaxValidators: 100, PowerUnit: types.GWeiAmount(1)}
}

// StakeToPower convierte stake a poder de voto (saturando en MaxTotalPower).
func (p StakingParams) StakeToPower(stake types.Amount) uint64 {
	unit := p.PowerUnit
	if unit.IsZero() {
		unit = types.NewAmount(1)
	}
	q := stake.Div(unit)
	if !q.IsUint64() || q.Uint64() > MaxTotalPower {
		return MaxTotalPower
	}
	return q.Uint64()
}

// ValidatorSetFromRecords construye el conjunto a partir de fichas de
// staking según las reglas descritas arriba.
func ValidatorSetFromRecords(records []*execution.ValidatorRecord, p StakingParams) (*ValidatorSet, error) {
	type cand struct {
		rec *execution.ValidatorRecord
		pk  *crypto.BLSPublicKey
	}
	cands := make([]cand, 0, len(records))
	for _, r := range records {
		if r == nil || r.Status != execution.ValidatorActive || r.Stake.Lt(p.MinStake) || r.Stake.IsZero() {
			continue
		}
		pk, err := crypto.BLSPublicKeyFromBytes(r.BLSKey)
		if err != nil {
			continue // el contrato ya lo valida; defensa en profundidad
		}
		cands = append(cands, cand{r, pk})
	}
	sort.Slice(cands, func(i, j int) bool {
		if c := cands[i].rec.Stake.Cmp(cands[j].rec.Stake); c != 0 {
			return c > 0
		}
		return bytes.Compare(cands[i].rec.Address[:], cands[j].rec.Address[:]) < 0
	})
	if p.MaxValidators > 0 && len(cands) > p.MaxValidators {
		cands = cands[:p.MaxValidators]
	}
	vals := make([]*Validator, 0, len(cands))
	var total uint64
	for _, c := range cands {
		pw := p.StakeToPower(c.rec.Stake)
		if pw == 0 {
			continue
		}
		if total+pw > MaxTotalPower {
			pw = MaxTotalPower - total
			if pw == 0 {
				break
			}
		}
		total += pw
		vals = append(vals, &Validator{Address: c.rec.Address, PubKey: c.pk, Power: pw})
	}
	return NewValidatorSet(vals)
}

// ValidatorSetFromState lee todas las fichas del estado y construye el
// conjunto.
func ValidatorSetFromState(st execution.StakingReader, p StakingParams) (*ValidatorSet, error) {
	return ValidatorSetFromRecords(execution.ReadAllValidators(st), p)
}

// GenesisValidator describe un validador inicial.
type GenesisValidator struct {
	Address types.Address
	BLSKey  *crypto.BLSPublicKey
	Stake   types.Amount
}

// InstallGenesisValidators escribe directamente en el estado las fichas de
// los validadores del génesis (sin pasar por register(), porque en el
// bloque 0 no hay transacciones) y acredita el stake al contrato para que
// su saldo respalde siempre stake + desvinculado.
func InstallGenesisValidators(st execution.StakingWriter, vals []GenesisValidator) error {
	total := execution.TotalStake(st)
	for _, v := range vals {
		if v.BLSKey == nil || v.Stake.IsZero() {
			return fmt.Errorf("consenso: validador génesis %s inválido", v.Address.Hex())
		}
		if _, exists := execution.ReadValidator(st, v.Address); exists {
			return fmt.Errorf("%w: %s", ErrDuplicateValidator, v.Address.Hex())
		}
		execution.WriteValidator(st, &execution.ValidatorRecord{
			Address: v.Address, BLSKey: v.BLSKey.Bytes(), Stake: v.Stake, Status: execution.ValidatorActive,
		})
		st.AddBalance(execution.StakingContractAddress, v.Stake)
		total = total.Add(v.Stake)
	}
	execution.SetTotalStake(st, total)
	return nil
}

// ValidatorPubKey devuelve la clave BLS registrada de una cuenta (la usa la
// verificación de evidencias, que no depende del conjunto de una época).
func ValidatorPubKey(st execution.StakingReader, addr types.Address) (*crypto.BLSPublicKey, *execution.ValidatorRecord, error) {
	r, ok := execution.ReadValidator(st, addr)
	if !ok {
		return nil, nil, ErrNotValidator
	}
	pk, err := crypto.BLSPublicKeyFromBytes(r.BLSKey)
	if err != nil {
		return nil, nil, err
	}
	return pk, r, nil
}
