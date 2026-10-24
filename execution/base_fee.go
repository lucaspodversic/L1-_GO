package execution

// Este archivo implementa la regla de ajuste de la base fee de EIP-1559 y
// las validaciones de cabecera asociadas (límite de gas y base fee).
//
// Regla: con objetivo = gasLimit/elasticidad, si el bloque padre usó más
// gas que el objetivo la base fee sube proporcionalmente (hasta 12,5 %, y
// al menos 1 wei); si usó menos, baja proporcionalmente. En esta cadena la
// base fee nunca baja de FeeConfig.MinBaseFee.

import (
	"fmt"
	"math/big"

	"github.com/l1/l1/types"
)

// CalcBaseFee calcula la base fee del hijo de parent.
func CalcBaseFee(cfg FeeConfig, parent *types.Header) types.Amount {
	elasticity := cfg.ElasticityMultiplier
	if elasticity == 0 {
		elasticity = types.ElasticityMultiplier
	}
	denom := cfg.BaseFeeChangeDenominator
	if denom == 0 {
		denom = types.BaseFeeChangeDenominator
	}
	parentBase := parent.BaseFee
	if parentBase.IsZero() {
		parentBase = cfg.InitialBaseFee
	}
	target := parent.GasLimit / elasticity
	var next types.Amount
	switch {
	case target == 0 || parent.GasUsed == target:
		next = parentBase
	case parent.GasUsed > target:
		// delta = max(base · (usado - objetivo) / objetivo / denom, 1)
		num := new(big.Int).Mul(parentBase.Big(), new(big.Int).SetUint64(parent.GasUsed-target))
		num.Div(num, new(big.Int).SetUint64(target))
		num.Div(num, new(big.Int).SetUint64(denom))
		if num.Sign() == 0 {
			num.SetUint64(1)
		}
		sum := new(big.Int).Add(parentBase.Big(), num)
		a, err := types.AmountFromBig(sum)
		if err != nil { // saturación (inalcanzable en la práctica)
			a = types.MustAmountFromBig(new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1)))
		}
		next = a
	default:
		num := new(big.Int).Mul(parentBase.Big(), new(big.Int).SetUint64(target-parent.GasUsed))
		num.Div(num, new(big.Int).SetUint64(target))
		num.Div(num, new(big.Int).SetUint64(denom))
		diff := new(big.Int).Sub(parentBase.Big(), num)
		if diff.Sign() < 0 {
			diff.SetUint64(0)
		}
		next = types.MustAmountFromBig(diff)
	}
	if next.Lt(cfg.MinBaseFee) {
		next = cfg.MinBaseFee
	}
	return next
}

// VerifyGasLimit comprueba que el límite de gas del hijo esté dentro de
// ±parent/1024 y de los límites absolutos.
func VerifyGasLimit(parentGasLimit, headerGasLimit uint64) error {
	diff := int64(parentGasLimit) - int64(headerGasLimit)
	if diff < 0 {
		diff = -diff
	}
	limit := parentGasLimit / types.GasLimitBoundDivisor
	if uint64(diff) >= limit {
		return fmt.Errorf("límite de gas inválido: tiene %d, padre %d, cambio máximo %d", headerGasLimit, parentGasLimit, limit-1)
	}
	if headerGasLimit < types.MinGasLimit {
		return fmt.Errorf("límite de gas %d inferior al mínimo %d", headerGasLimit, types.MinGasLimit)
	}
	if headerGasLimit > types.MaxGasLimit {
		return fmt.Errorf("límite de gas %d superior al máximo", headerGasLimit)
	}
	return nil
}

// VerifyEIP1559Header valida límite de gas, gas usado y base fee de header
// respecto de su padre.
func VerifyEIP1559Header(cfg FeeConfig, parent, header *types.Header) error {
	if err := VerifyGasLimit(parent.GasLimit, header.GasLimit); err != nil {
		return err
	}
	if header.GasUsed > header.GasLimit {
		return fmt.Errorf("gas usado %d supera el límite %d", header.GasUsed, header.GasLimit)
	}
	expected := CalcBaseFee(cfg, parent)
	if !header.BaseFee.Eq(expected) {
		return fmt.Errorf("base fee inválida: tiene %s, se esperaba %s (padre %s, usado %d/%d)",
			header.BaseFee, expected, parent.BaseFee, parent.GasUsed, parent.GasLimit)
	}
	return nil
}

// CalcGasLimit acerca el límite del padre al deseado sin superar el paso
// máximo permitido (parent/1024 - 1). Lo usa el proponente al construir.
func CalcGasLimit(parentGasLimit, desiredLimit uint64) uint64 {
	delta := parentGasLimit/types.GasLimitBoundDivisor - 1
	limit := parentGasLimit
	if desiredLimit < types.MinGasLimit {
		desiredLimit = types.MinGasLimit
	}
	if limit < desiredLimit {
		limit = parentGasLimit + delta
		if limit > desiredLimit {
			limit = desiredLimit
		}
		return limit
	}
	if limit > desiredLimit {
		limit = parentGasLimit - delta
		if limit < desiredLimit {
			limit = desiredLimit
		}
	}
	return limit
}
