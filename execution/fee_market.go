package execution

// Este archivo define el mercado de comisiones EIP-1559 de la cadena:
//
//   - FeeConfig: parámetros (base fee inicial y mínima, denominador de
//     cambio, elasticidad y destino de la base fee: quema o tesorería).
//   - Reparto de comisiones de una transacción: la base fee se quema (o va
//     a la tesorería) y la propina efectiva va al proponente (coinbase).
//   - GasPriceOracle: sugiere maxPriorityFeePerGas/maxFeePerGas a partir de
//     las propinas pagadas en los últimos bloques (eth_gasPrice,
//     eth_maxPriorityFeePerGas, eth_feeHistory).

import (
	"sort"
	"sync"

	"github.com/l1/l1/types"
)

// FeeConfig son los parámetros del mercado de comisiones.
type FeeConfig struct {
	// InitialBaseFee es la base fee del bloque génesis si no se indica otra.
	InitialBaseFee types.Amount
	// MinBaseFee es el suelo de la base fee (evita que caiga a cero y el
	// spam sea gratis en una cadena poco usada).
	MinBaseFee types.Amount
	// BaseFeeChangeDenominator limita el cambio por bloque a 1/denominador
	// (1/8 = 12,5 %).
	BaseFeeChangeDenominator uint64
	// ElasticityMultiplier: objetivo de gas = límite / elasticidad.
	ElasticityMultiplier uint64
	// Treasury, si no es cero, recibe la base fee en lugar de quemarla.
	Treasury types.Address
}

// DefaultFeeConfig usa las constantes del paquete types.
func DefaultFeeConfig() FeeConfig {
	return FeeConfig{
		InitialBaseFee:           types.NewAmount(types.InitialBaseFee),
		MinBaseFee:               types.NewAmount(types.MinBaseFee),
		BaseFeeChangeDenominator: types.BaseFeeChangeDenominator,
		ElasticityMultiplier:     types.ElasticityMultiplier,
	}
}

// BurnsBaseFee informa si la base fee se quema.
func (c FeeConfig) BurnsBaseFee() bool { return c.Treasury == (types.Address{}) }

// FeeSplit es el reparto de las comisiones de una transacción.
type FeeSplit struct {
	// Burned es baseFee · gasUsed (quemado o a la tesorería).
	Burned types.Amount
	// Tip es propinaEfectiva · gasUsed (al proponente).
	Tip types.Amount
}

// Total devuelve lo que pagó el remitente en comisiones.
func (f FeeSplit) Total() types.Amount { return f.Burned.Add(f.Tip) }

// SplitFees calcula el reparto para gasUsed unidades.
func SplitFees(baseFee, effectiveTip types.Amount, gasUsed uint64) FeeSplit {
	return FeeSplit{Burned: baseFee.MulUint64(gasUsed), Tip: effectiveTip.MulUint64(gasUsed)}
}

// ---------------------------------------------------------------------------
// Oráculo de precio del gas
// ---------------------------------------------------------------------------

// OracleConfig parametriza el oráculo.
type OracleConfig struct {
	// Blocks es cuántos bloques recientes se consideran.
	Blocks int
	// Percentile de las propinas a sugerir (0-100).
	Percentile int
	// Default es la propina sugerida sin datos.
	Default types.Amount
	// MaxTip acota la sugerencia (protege de picos).
	MaxTip types.Amount
	// IgnoreBelow descarta propinas menores (txs del propio proponente…).
	IgnoreBelow types.Amount
}

// DefaultOracleConfig: 20 bloques, percentil 60, 1 gwei por defecto, 500
// gwei de máximo, ignora propinas < 2 wei.
func DefaultOracleConfig() OracleConfig {
	return OracleConfig{
		Blocks: 20, Percentile: 60,
		Default: types.GWeiAmount(1), MaxTip: types.GWeiAmount(500), IgnoreBelow: types.NewAmount(2),
	}
}

// blockFeeSample resume las comisiones de un bloque.
type blockFeeSample struct {
	number       uint64
	baseFee      types.Amount
	gasUsedRatio float64
	tips         []types.Amount // ordenadas de menor a mayor
}

// GasPriceOracle mantiene una ventana de bloques recientes. Es seguro para
// uso concurrente.
type GasPriceOracle struct {
	mu      sync.RWMutex
	cfg     OracleConfig
	samples []blockFeeSample // ventana circular simple (más reciente al final)
	fees    FeeConfig
}

// NewGasPriceOracle crea el oráculo.
func NewGasPriceOracle(cfg OracleConfig, fees FeeConfig) *GasPriceOracle {
	if cfg.Blocks <= 0 {
		cfg.Blocks = 20
	}
	if cfg.Percentile < 0 || cfg.Percentile > 100 {
		cfg.Percentile = 60
	}
	return &GasPriceOracle{cfg: cfg, fees: fees}
}

// AddBlock incorpora un bloque. Las propinas se calculan con la base fee
// de su cabecera.
func (o *GasPriceOracle) AddBlock(b *types.Block) {
	h := b.HeaderRef()
	s := blockFeeSample{number: h.Number, baseFee: h.BaseFee}
	if h.GasLimit > 0 {
		s.gasUsedRatio = float64(h.GasUsed) / float64(h.GasLimit)
	}
	for _, tx := range b.Transactions() {
		tip, err := tx.EffectiveGasTip(h.BaseFee)
		if err != nil || tip.Lt(o.cfg.IgnoreBelow) {
			continue
		}
		s.tips = append(s.tips, tip)
	}
	sort.Slice(s.tips, func(i, j int) bool { return s.tips[i].Lt(s.tips[j]) })
	o.mu.Lock()
	defer o.mu.Unlock()
	o.samples = append(o.samples, s)
	if len(o.samples) > o.cfg.Blocks {
		o.samples = append([]blockFeeSample(nil), o.samples[len(o.samples)-o.cfg.Blocks:]...)
	}
}

// percentileOf devuelve el percentil p de una lista ordenada.
func percentileOf(sorted []types.Amount, p int) types.Amount {
	if len(sorted) == 0 {
		return types.Amount{}
	}
	idx := (len(sorted) - 1) * p / 100
	return sorted[idx]
}

// SuggestTipCap sugiere maxPriorityFeePerGas: el percentil configurado de
// la propina más baja de cada bloque reciente (lo mínimo que hizo falta
// para entrar), acotado por MaxTip. Los bloques vacíos no aportan.
func (o *GasPriceOracle) SuggestTipCap() types.Amount {
	o.mu.RLock()
	defer o.mu.RUnlock()
	var mins []types.Amount
	for _, s := range o.samples {
		if len(s.tips) > 0 {
			mins = append(mins, s.tips[0])
		}
	}
	if len(mins) == 0 {
		return o.cfg.Default
	}
	sort.Slice(mins, func(i, j int) bool { return mins[i].Lt(mins[j]) })
	tip := percentileOf(mins, o.cfg.Percentile)
	if !o.cfg.MaxTip.IsZero() && tip.Gt(o.cfg.MaxTip) {
		tip = o.cfg.MaxTip
	}
	return tip
}

// SuggestFeeCap sugiere maxFeePerGas = 2·baseFee(siguiente) + propina: deja
// margen para seis bloques llenos seguidos (+12,5 % cada uno).
func (o *GasPriceOracle) SuggestFeeCap(nextBaseFee types.Amount) types.Amount {
	return nextBaseFee.MulUint64(2).Add(o.SuggestTipCap())
}

// SuggestGasPrice sugiere un gasPrice legacy: baseFee + propina.
func (o *GasPriceOracle) SuggestGasPrice(nextBaseFee types.Amount) types.Amount {
	return nextBaseFee.Add(o.SuggestTipCap())
}

// FeeHistoryEntry es una fila de eth_feeHistory.
type FeeHistoryEntry struct {
	Number       uint64
	BaseFee      types.Amount
	GasUsedRatio float64
	Rewards      []types.Amount // propina en cada percentil pedido
}

// FeeHistory devuelve hasta n bloques recientes con las propinas en los
// percentiles indicados.
func (o *GasPriceOracle) FeeHistory(n int, percentiles []int) []FeeHistoryEntry {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if n <= 0 || n > len(o.samples) {
		n = len(o.samples)
	}
	out := make([]FeeHistoryEntry, 0, n)
	for _, s := range o.samples[len(o.samples)-n:] {
		e := FeeHistoryEntry{Number: s.number, BaseFee: s.baseFee, GasUsedRatio: s.gasUsedRatio}
		for _, p := range percentiles {
			e.Rewards = append(e.Rewards, percentileOf(s.tips, p))
		}
		out = append(out, e)
	}
	return out
}
