package consensus

// Este archivo valida las reglas de consenso de una cabecera respecto a su
// padre, sin ejecutar el bloque ni verificar firmas:
//
//   - Límites de forma (Header.SanityCheck): ExtraData, rango del gas.
//   - Encadenamiento: altura = padre + 1 y ParentHash correcto.
//   - Tiempo: Timestamp >= el del padre (se admite igualdad porque con
//     bloques sub-segundo dos alturas pueden compartir segundo) y no más de
//     MaxFutureDrift por delante del reloj local.
//   - Consenso: vista estrictamente creciente, época = altura / longitud,
//     proponente no nulo y JustifyHash presente.
//   - Mercado de comisiones EIP-1559: límite de gas dentro del paso
//     permitido y base fee exacta (execution.VerifyEIP1559Header).
//   - Con la época conocida: ValidatorsHash coincide con el conjunto y el
//     proponente pertenece a él.

import (
	"errors"
	"fmt"
	"time"

	"github.com/l1/l1/execution"
	"github.com/l1/l1/types"
)

// ErrInvalidHeader agrupa los fallos de cabecera.
var ErrInvalidHeader = errors.New("consenso: cabecera inválida")

// HeaderValidator valida cabeceras.
type HeaderValidator struct {
	ChainID types.ChainID
	Epochs  EpochParams
	Fees    execution.FeeConfig
	// MaxFutureDrift es la tolerancia de reloj hacia el futuro.
	MaxFutureDrift time.Duration
	// Now devuelve la hora local (inyectable en pruebas).
	Now func() time.Time
}

// NewHeaderValidator crea un validador con 15 s de tolerancia.
func NewHeaderValidator(chainID types.ChainID, epochs EpochParams, fees execution.FeeConfig) *HeaderValidator {
	return &HeaderValidator{ChainID: chainID, Epochs: epochs, Fees: fees, MaxFutureDrift: 15 * time.Second, Now: time.Now}
}

// headerErr envuelve un fallo de cabecera con contexto.
func headerErr(h *types.Header, format string, args ...any) error {
	return fmt.Errorf("%w (#%d): %s", ErrInvalidHeader, h.Number, fmt.Sprintf(format, args...))
}

// VerifyHeader comprueba las reglas independientes del conjunto de
// validadores.
func (v *HeaderValidator) VerifyHeader(header, parent *types.Header) error {
	if err := header.SanityCheck(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidHeader, err)
	}
	if header.Number != parent.Number+1 {
		return headerErr(header, "altura %d tras %d", header.Number, parent.Number)
	}
	if header.ParentHash != parent.Hash() {
		return headerErr(header, "parentHash %s, se esperaba %s", header.ParentHash.Hex(), parent.Hash().Hex())
	}
	if header.Timestamp < parent.Timestamp {
		return headerErr(header, "marca de tiempo %d anterior a la del padre %d", header.Timestamp, parent.Timestamp)
	}
	now := time.Now
	if v.Now != nil {
		now = v.Now
	}
	if limit := now().Add(v.MaxFutureDrift).Unix(); limit >= 0 && header.Timestamp > uint64(limit) {
		return headerErr(header, "marca de tiempo %d demasiado en el futuro", header.Timestamp)
	}
	if header.View <= parent.View {
		return headerErr(header, "vista %d no supera la del padre %d", header.View, parent.View)
	}
	if want := v.Epochs.EpochOf(header.Number); header.Epoch != want {
		return headerErr(header, "época %d, se esperaba %d", header.Epoch, want)
	}
	if header.Proposer == (types.Address{}) {
		return headerErr(header, "proponente nulo")
	}
	if header.JustifyHash == (types.Hash{}) {
		return headerErr(header, "sin JustifyHash")
	}
	if err := execution.VerifyEIP1559Header(v.Fees, parent, header); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidHeader, err)
	}
	return nil
}

// VerifyHeaderWithEpoch añade las comprobaciones que dependen del conjunto
// de validadores de la época de la cabecera.
func (v *HeaderValidator) VerifyHeaderWithEpoch(header, parent *types.Header, info *EpochInfo) error {
	if err := v.VerifyHeader(header, parent); err != nil {
		return err
	}
	if info == nil || info.Epoch != header.Epoch {
		return fmt.Errorf("%w: %d", ErrUnknownEpoch, header.Epoch)
	}
	if header.ValidatorsHash != info.Validators.Hash() {
		return headerErr(header, "validatorsHash %s, se esperaba %s", header.ValidatorsHash.Hex(), info.Validators.Hash().Hex())
	}
	if !info.Validators.Contains(header.Proposer) {
		return headerErr(header, "proponente %s no es validador", header.Proposer.Hex())
	}
	return nil
}
