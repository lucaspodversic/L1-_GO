package types

// Este archivo define Header, la cabecera de bloque. Su hash identifica al
// bloque y es lo que firman/votan los validadores en el consenso BFT.
//
// Además de los campos clásicos (padre, número, raíces, gas, base fee), la
// cabecera lleva metadatos del consenso estilo HotStuff:
//
//   - Epoch: época vigente (cambia el conjunto de validadores cada N bloques).
//   - View: número de vista/ronda en que se propuso; con un líder por vista,
//     permite verificar que el proponente era el correcto.
//   - ValidatorsHash: compromiso con el conjunto de validadores de la época.
//   - JustifyHash: Keccak256 del QC (Quorum Certificate) que certifica al
//     padre; el QC completo viaja en Block.Justify.
//   - Random: aleatoriedad del bloque (salida VRF del proponente); se expone
//     a la VM como PREVRANDAO.

import (
	"fmt"
	"sync/atomic"
)

// Header es la cabecera de un bloque.
type Header struct {
	// ParentHash es el hash de la cabecera del bloque padre.
	ParentHash Hash `json:"parentHash"`
	// Number es la altura (génesis = 0).
	Number uint64 `json:"number"`
	// Timestamp es la hora de propuesta en segundos Unix (lo que ve la VM).
	Timestamp uint64 `json:"timestamp"`
	// Proposer es la dirección que cobra las propinas (coinbase).
	Proposer Address `json:"proposer"`
	// StateRoot es la raíz del trie de estado DESPUÉS de ejecutar el bloque.
	StateRoot Hash `json:"stateRoot"`
	// TxRoot es la raíz del trie de transacciones.
	TxRoot Hash `json:"transactionsRoot"`
	// ReceiptRoot es la raíz del trie de recibos.
	ReceiptRoot Hash `json:"receiptsRoot"`
	// LogsBloom es la unión de los Bloom de todos los recibos.
	LogsBloom Bloom `json:"logsBloom"`
	// GasLimit es el máximo de gas del bloque.
	GasLimit uint64 `json:"gasLimit"`
	// GasUsed es el gas efectivamente consumido.
	GasUsed uint64 `json:"gasUsed"`
	// BaseFee es el base fee por gas de EIP-1559 (se quema).
	BaseFee Amount `json:"baseFeePerGas"`
	// ExtraData es un campo libre acotado (MaxExtraDataSize).
	ExtraData HexBytes `json:"extraData"`
	// Epoch es la época de consenso.
	Epoch uint64 `json:"epoch"`
	// View es la vista (ronda) de consenso en que se propuso.
	View uint64 `json:"view"`
	// ValidatorsHash compromete al conjunto de validadores de la época.
	ValidatorsHash Hash `json:"validatorsHash"`
	// JustifyHash es el hash del QC del padre (cero en el génesis).
	JustifyHash Hash `json:"justifyHash"`
	// Random es la aleatoriedad del bloque (PREVRANDAO).
	Random Hash `json:"random"`

	// hash cachea Hash().
	hash atomic.Pointer[Hash]
}

// headerFields es la cantidad de campos RLP de la cabecera.
const headerFields = 17

// Copy devuelve una copia profunda sin caché.
func (h *Header) Copy() *Header {
	return &Header{
		ParentHash: h.ParentHash, Number: h.Number, Timestamp: h.Timestamp, Proposer: h.Proposer,
		StateRoot: h.StateRoot, TxRoot: h.TxRoot, ReceiptRoot: h.ReceiptRoot, LogsBloom: h.LogsBloom,
		GasLimit: h.GasLimit, GasUsed: h.GasUsed, BaseFee: h.BaseFee, ExtraData: append(HexBytes(nil), h.ExtraData...),
		Epoch: h.Epoch, View: h.View, ValidatorsHash: h.ValidatorsHash, JustifyHash: h.JustifyHash, Random: h.Random,
	}
}

// EncodeRLP codifica la cabecera (el orden de campos es de consenso).
func (h *Header) EncodeRLP() []byte {
	return EncodeList(
		h.ParentHash.EncodeRLP(), EncodeUint(h.Number), EncodeUint(h.Timestamp), h.Proposer.EncodeRLP(),
		h.StateRoot.EncodeRLP(), h.TxRoot.EncodeRLP(), h.ReceiptRoot.EncodeRLP(), EncodeBytes(h.LogsBloom[:]),
		EncodeUint(h.GasLimit), EncodeUint(h.GasUsed), h.BaseFee.EncodeRLP(), EncodeBytes(h.ExtraData),
		EncodeUint(h.Epoch), EncodeUint(h.View), h.ValidatorsHash.EncodeRLP(), h.JustifyHash.EncodeRLP(), h.Random.EncodeRLP(),
	)
}

// DecodeHeader decodifica una cabecera desde RLP.
func DecodeHeader(b []byte) (*Header, error) {
	it, err := DecodeRLP(b)
	if err != nil {
		return nil, err
	}
	return decodeHeaderItem(it)
}

// decodeHeaderItem decodifica desde un ítem ya parseado (para el bloque).
func decodeHeaderItem(it RLPItem) (*Header, error) {
	f, err := it.ListN(headerFields)
	if err != nil {
		return nil, err
	}
	h := &Header{}
	// Pequeños helpers para no repetir "if err != nil" 17 veces.
	hashes := []*Hash{&h.ParentHash, &h.StateRoot, &h.TxRoot, &h.ReceiptRoot, &h.ValidatorsHash, &h.JustifyHash, &h.Random}
	hashIdx := []int{0, 4, 5, 6, 14, 15, 16}
	for i, p := range hashes {
		if *p, err = f[hashIdx[i]].Hash(); err != nil {
			return nil, fmt.Errorf("header campo %d: %w", hashIdx[i], err)
		}
	}
	uints := []*uint64{&h.Number, &h.Timestamp, &h.GasLimit, &h.GasUsed, &h.Epoch, &h.View}
	uintIdx := []int{1, 2, 8, 9, 12, 13}
	for i, p := range uints {
		if *p, err = f[uintIdx[i]].Uint64(); err != nil {
			return nil, fmt.Errorf("header campo %d: %w", uintIdx[i], err)
		}
	}
	if h.Proposer, err = f[3].Address(); err != nil {
		return nil, err
	}
	bl, err := f[7].Bytes()
	if err != nil {
		return nil, err
	}
	if len(bl) != BloomByteLength {
		return nil, ErrInvalidLength
	}
	copy(h.LogsBloom[:], bl)
	if h.BaseFee, err = DecodeAmountRLP(f[10]); err != nil {
		return nil, err
	}
	if h.ExtraData, err = f[11].BytesCopy(); err != nil {
		return nil, err
	}
	return h, nil
}

// Hash devuelve Keccak256(RLP(header)), cacheado. Modificar la cabecera
// después de llamar a Hash deja la caché obsoleta: usar Copy.
func (h *Header) Hash() Hash {
	if p := h.hash.Load(); p != nil {
		return *p
	}
	v := Keccak256Hash(h.EncodeRLP())
	h.hash.Store(&v)
	return v
}

// SanityCheck valida límites que no requieren contexto (padre, estado):
// tamaño de ExtraData, GasUsed <= GasLimit y rango del GasLimit.
func (h *Header) SanityCheck() error {
	if len(h.ExtraData) > MaxExtraDataSize {
		return newValidationError(nil, "header", "extraData", "%d bytes supera %d", len(h.ExtraData), MaxExtraDataSize)
	}
	if h.GasLimit < MinGasLimit || h.GasLimit > MaxGasLimit {
		return newValidationError(nil, "header", "gasLimit", "%d fuera de rango", h.GasLimit)
	}
	if h.GasUsed > h.GasLimit {
		return newValidationError(nil, "header", "gasUsed", "%d supera el límite %d", h.GasUsed, h.GasLimit)
	}
	return nil
}

// String devuelve un resumen para logs.
func (h *Header) String() string {
	return fmt.Sprintf("#%d %s (view %d, epoch %d, txroot %s)", h.Number, h.Hash().TerminalString(), h.View, h.Epoch, h.TxRoot.TerminalString())
}
