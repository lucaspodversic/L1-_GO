package types

// Este archivo define el resultado de ejecutar una transacción: Receipt
// (recibo), Log (evento emitido por un contrato) y Bloom (filtro probabilístico
// que permite descartar rápido bloques que no contienen un evento buscado).
//
// Un recibo tiene dos codificaciones:
//
//   - De consenso (MarshalBinary): [status, cumulativeGasUsed, bloom, logs],
//     con el mismo sobre tipado que la transacción. Es la que entra en la
//     ReceiptRoot de la cabecera; por eso contiene sólo datos deterministas.
//   - De almacenamiento (EncodeStorage): agrega datos que se pueden derivar
//     pero que conviene persistir (hash de la tx, gas usado, dirección del
//     contrato creado, precio efectivo). El resto (hash/número de bloque,
//     índices) se completa al leer, con DeriveFields.

import (
	"fmt"
)

// Estados posibles de un recibo.
const (
	// ReceiptStatusFailed indica que la ejecución revirtió (se cobra el gas igual).
	ReceiptStatusFailed uint64 = 0
	// ReceiptStatusSuccessful indica ejecución exitosa.
	ReceiptStatusSuccessful uint64 = 1
)

// Log es un evento emitido por LOG0..LOG4 en la VM.
type Log struct {
	// --- Campos de consenso ---

	// Address es el contrato que emitió el evento.
	Address Address `json:"address"`
	// Topics son hasta 4 palabras indexadas (la primera suele ser la firma del evento).
	Topics []Hash `json:"topics"`
	// Data son los datos no indexados.
	Data HexBytes `json:"data"`

	// --- Campos derivados (no se hashean) ---

	// BlockNumber es el número del bloque que lo incluye.
	BlockNumber uint64 `json:"blockNumber"`
	// TxHash es la transacción que lo generó.
	TxHash Hash `json:"transactionHash"`
	// TxIndex es la posición de esa transacción en el bloque.
	TxIndex uint `json:"transactionIndex"`
	// BlockHash es el hash del bloque.
	BlockHash Hash `json:"blockHash"`
	// Index es la posición del log dentro del bloque.
	Index uint `json:"logIndex"`
	// Removed es true si el log quedó fuera por una reorganización.
	Removed bool `json:"removed"`
}

// encodeRLP codifica los campos de consenso: [address, [topics], data].
func (l *Log) encodeRLP() []byte {
	topics := make([][]byte, len(l.Topics))
	for i, t := range l.Topics {
		topics[i] = t.EncodeRLP()
	}
	return EncodeList(l.Address.EncodeRLP(), EncodeList(topics...), EncodeBytes(l.Data))
}

// decodeLog decodifica los campos de consenso de un log.
func decodeLog(it RLPItem) (*Log, error) {
	f, err := it.ListN(3)
	if err != nil {
		return nil, err
	}
	l := &Log{}
	if l.Address, err = f[0].Address(); err != nil {
		return nil, err
	}
	ts, err := f[1].Items()
	if err != nil {
		return nil, err
	}
	if len(ts) > 4 {
		return nil, fmt.Errorf("log con %d topics (máx. 4)", len(ts))
	}
	for _, t := range ts {
		h, err := t.Hash()
		if err != nil {
			return nil, err
		}
		l.Topics = append(l.Topics, h)
	}
	if l.Data, err = f[2].BytesCopy(); err != nil {
		return nil, err
	}
	return l, nil
}

// Bloom es un filtro de Bloom de 2048 bits sobre direcciones y topics.
// Para cada valor se calculan 3 bits a partir de Keccak256(valor): permite
// responder "seguro que no está" o "quizás está" sin recorrer los logs.
type Bloom [BloomByteLength]byte

// bloomBits devuelve las 3 posiciones (índice de byte y máscara) para d.
func bloomBits(d []byte) (idx [3]int, mask [3]byte) {
	h := Keccak256(d)
	for i := 0; i < 3; i++ {
		// Se toman 11 bits (0..2047) de cada par de bytes del hash.
		bit := (uint(h[2*i])<<8 | uint(h[2*i+1])) & 2047
		idx[i] = BloomByteLength - 1 - int(bit/8) // big-endian: bit 0 en el último byte
		mask[i] = 1 << (bit % 8)
	}
	return
}

// Add incorpora d al filtro.
func (b *Bloom) Add(d []byte) {
	idx, mask := bloomBits(d)
	for i := 0; i < 3; i++ {
		b[idx[i]] |= mask[i]
	}
}

// Test informa si d PODRÍA estar en el filtro (falsos positivos posibles,
// falsos negativos imposibles).
func (b Bloom) Test(d []byte) bool {
	idx, mask := bloomBits(d)
	for i := 0; i < 3; i++ {
		if b[idx[i]]&mask[i] == 0 {
			return false
		}
	}
	return true
}

// Or combina dos filtros (unión), p. ej. para el Bloom del bloque.
func (b *Bloom) Or(o Bloom) {
	for i := range b {
		b[i] |= o[i]
	}
}

// Bytes devuelve una copia del filtro.
func (b Bloom) Bytes() []byte { return append([]byte(nil), b[:]...) }

// MarshalText implementa encoding.TextMarshaler.
func (b Bloom) MarshalText() ([]byte, error) { return []byte(EncodeHex(b[:])), nil }

// UnmarshalText implementa encoding.TextUnmarshaler.
func (b *Bloom) UnmarshalText(text []byte) error {
	v, err := DecodeHex(string(text))
	if err != nil {
		return err
	}
	if len(v) != BloomByteLength {
		return ErrInvalidLength
	}
	copy(b[:], v)
	return nil
}

// LogsBloom calcula el Bloom de una lista de logs.
func LogsBloom(logs []*Log) Bloom {
	var b Bloom
	for _, l := range logs {
		b.Add(l.Address[:])
		for _, t := range l.Topics {
			b.Add(t[:])
		}
	}
	return b
}

// Receipt es el resultado de ejecutar una transacción.
type Receipt struct {
	// --- Campos de consenso ---

	// Type replica el tipo de la transacción.
	Type TxType `json:"type"`
	// Status es ReceiptStatusSuccessful o ReceiptStatusFailed.
	Status uint64 `json:"status"`
	// CumulativeGasUsed es el gas acumulado del bloque hasta esta tx inclusive.
	CumulativeGasUsed uint64 `json:"cumulativeGasUsed"`
	// Bloom es el filtro de los logs de esta tx.
	Bloom Bloom `json:"logsBloom"`
	// Logs son los eventos emitidos.
	Logs []*Log `json:"logs"`

	// --- Campos persistidos pero no de consenso ---

	// TxHash es el hash de la transacción.
	TxHash Hash `json:"transactionHash"`
	// ContractAddress es la dirección creada (si fue despliegue).
	ContractAddress Address `json:"contractAddress"`
	// GasUsed es el gas consumido sólo por esta tx.
	GasUsed uint64 `json:"gasUsed"`
	// EffectiveGasPrice es baseFee + propina efectivamente pagada.
	EffectiveGasPrice Amount `json:"effectiveGasPrice"`

	// --- Campos derivados al leer ---

	// BlockHash es el bloque que la incluye.
	BlockHash Hash `json:"blockHash"`
	// BlockNumber es el número de ese bloque.
	BlockNumber uint64 `json:"blockNumber"`
	// TxIndex es la posición en el bloque.
	TxIndex uint `json:"transactionIndex"`
}

// consensusList codifica [status, cumGas, bloom, logs].
func (r *Receipt) consensusList() []byte {
	logs := make([][]byte, len(r.Logs))
	for i, l := range r.Logs {
		logs[i] = l.encodeRLP()
	}
	return EncodeList(EncodeUint(r.Status), EncodeUint(r.CumulativeGasUsed), EncodeBytes(r.Bloom[:]), EncodeList(logs...))
}

// MarshalBinary devuelve la codificación de consenso (con sobre tipado).
func (r *Receipt) MarshalBinary() []byte {
	body := r.consensusList()
	if r.Type == LegacyTxType {
		return body
	}
	return append([]byte{byte(r.Type)}, body...)
}

// decodeConsensusFields llena los campos de consenso desde la lista.
func (r *Receipt) decodeConsensusFields(it RLPItem) error {
	f, err := it.ListN(4)
	if err != nil {
		return err
	}
	if r.Status, err = f[0].Uint64(); err != nil {
		return err
	}
	if r.CumulativeGasUsed, err = f[1].Uint64(); err != nil {
		return err
	}
	bl, err := f[2].Bytes()
	if err != nil {
		return err
	}
	if len(bl) != BloomByteLength {
		return ErrInvalidLength
	}
	copy(r.Bloom[:], bl)
	logs, err := f[3].Items()
	if err != nil {
		return err
	}
	r.Logs = make([]*Log, 0, len(logs))
	for _, li := range logs {
		l, err := decodeLog(li)
		if err != nil {
			return err
		}
		r.Logs = append(r.Logs, l)
	}
	return nil
}

// DecodeReceipt decodifica la forma de consenso.
func DecodeReceipt(b []byte) (*Receipt, error) {
	if len(b) == 0 {
		return nil, ErrRLPTruncated
	}
	r := &Receipt{}
	if b[0] < 0xc0 {
		r.Type = TxType(b[0])
		b = b[1:]
	}
	it, err := DecodeRLP(b)
	if err != nil {
		return nil, err
	}
	return r, r.decodeConsensusFields(it)
}

// EncodeStorage codifica para persistir: [type, consensus, txHash, contract, gasUsed, effPrice].
func (r *Receipt) EncodeStorage() []byte {
	return EncodeList(
		EncodeUint(uint64(r.Type)), r.consensusList(), r.TxHash.EncodeRLP(), r.ContractAddress.EncodeRLP(),
		EncodeUint(r.GasUsed), r.EffectiveGasPrice.EncodeRLP(),
	)
}

// DecodeStorageReceipt es la inversa de EncodeStorage.
func DecodeStorageReceipt(it RLPItem) (*Receipt, error) {
	f, err := it.ListN(6)
	if err != nil {
		return nil, err
	}
	r := &Receipt{}
	t, err := f[0].Uint64()
	if err != nil {
		return nil, err
	}
	r.Type = TxType(t)
	if err := r.decodeConsensusFields(f[1]); err != nil {
		return nil, err
	}
	if r.TxHash, err = f[2].Hash(); err != nil {
		return nil, err
	}
	if r.ContractAddress, err = f[3].Address(); err != nil {
		return nil, err
	}
	if r.GasUsed, err = f[4].Uint64(); err != nil {
		return nil, err
	}
	if r.EffectiveGasPrice, err = DecodeAmountRLP(f[5]); err != nil {
		return nil, err
	}
	return r, nil
}

// Receipts es la lista de recibos de un bloque; implementa DerivableList.
type Receipts []*Receipt

// Len implementa DerivableList.
func (rs Receipts) Len() int { return len(rs) }

// EncodeIndex implementa DerivableList con la codificación de consenso.
func (rs Receipts) EncodeIndex(i int) []byte { return rs[i].MarshalBinary() }

// Bloom devuelve la unión de los Bloom de todos los recibos (LogsBloom del bloque).
func (rs Receipts) Bloom() Bloom {
	var b Bloom
	for _, r := range rs {
		b.Or(r.Bloom)
	}
	return b
}

// DeriveFields completa los campos derivados de los recibos y sus logs a
// partir del bloque que los contiene. Exige que la cantidad coincida.
func (rs Receipts) DeriveFields(blockHash Hash, number uint64, txs Transactions) error {
	if len(rs) != len(txs) {
		return fmt.Errorf("recibos (%d) y transacciones (%d) no coinciden", len(rs), len(txs))
	}
	var logIndex uint
	for i, r := range rs {
		r.BlockHash, r.BlockNumber, r.TxIndex = blockHash, number, uint(i)
		r.TxHash = txs[i].Hash()
		// GasUsed se deduce de la diferencia de acumulados.
		if i == 0 {
			r.GasUsed = r.CumulativeGasUsed
		} else {
			r.GasUsed = r.CumulativeGasUsed - rs[i-1].CumulativeGasUsed
		}
		for _, l := range r.Logs {
			l.BlockHash, l.BlockNumber, l.TxHash, l.TxIndex, l.Index = blockHash, number, r.TxHash, uint(i), logIndex
			logIndex++
		}
	}
	return nil
}
