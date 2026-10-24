package types

// Este archivo define Transaction, la unidad de cambio de estado que firman
// los usuarios, junto con su codificación binaria, sus hashes y los cálculos
// de costo que usarán mempool y VM.
//
// # Tipos soportados (compatibles con Ethereum)
//
//   - LegacyTxType (0x00): RLP([nonce, gasPrice, gas, to, value, data, v, r, s])
//     con V según EIP-155 (incluye el chain id). Se exige EIP-155.
//   - DynamicFeeTxType (0x02, EIP-1559): 0x02 || RLP([chainId, nonce,
//     maxPriorityFeePerGas, maxFeePerGas, gas, to, value, data, accessList,
//     yParity, r, s]).
//
// Ambos formatos son byte a byte los de Ethereum, de modo que wallets
// existentes pueden firmar transacciones para esta cadena.
//
// # Modelo interno unificado
//
// Internamente hay un único struct con todos los campos. Para legacy,
// GasTipCap == GasFeeCap == gasPrice y AccessList queda vacía. Así VM y
// mempool no necesitan distinguir tipos salvo para codificar.
//
// # Inmutabilidad
//
// Una vez construida, una Transaction no debe modificarse: su hash y su
// remitente se cachean. Para "cambiar" campos se construye una nueva
// (ver Copy / WithSignature).

import (
	"errors"
	"fmt"
	"sync/atomic"
)

// TxType es el tipo de transacción (primer byte del sobre tipado).
type TxType uint8

const (
	// LegacyTxType es el formato original con gasPrice único.
	LegacyTxType TxType = 0x00
	// DynamicFeeTxType es el formato EIP-1559 con base fee + propina.
	DynamicFeeTxType TxType = 0x02
)

// AccessTuple declara por adelantado una dirección y slots que la
// transacción va a tocar (EIP-2930); abarata el primer acceso en la VM.
type AccessTuple struct {
	// Address es la cuenta accedida.
	Address Address `json:"address"`
	// StorageKeys son los slots de almacenamiento accedidos.
	StorageKeys []Hash `json:"storageKeys"`
}

// AccessList es la lista de accesos declarados.
type AccessList []AccessTuple

// StorageKeys devuelve la cantidad total de slots declarados.
func (al AccessList) StorageKeys() int {
	n := 0
	for _, t := range al {
		n += len(t.StorageKeys)
	}
	return n
}

// encodeRLP codifica la access list como [[address, [key...]]...].
func (al AccessList) encodeRLP() []byte {
	items := make([][]byte, len(al))
	for i, t := range al {
		keys := make([][]byte, len(t.StorageKeys))
		for j, k := range t.StorageKeys {
			keys[j] = k.EncodeRLP()
		}
		items[i] = EncodeList(t.Address.EncodeRLP(), EncodeList(keys...))
	}
	return EncodeList(items...)
}

// decodeAccessList es la inversa de encodeRLP.
func decodeAccessList(it RLPItem) (AccessList, error) {
	tuples, err := it.Items()
	if err != nil {
		return nil, err
	}
	al := make(AccessList, 0, len(tuples))
	for _, t := range tuples {
		f, err := t.ListN(2)
		if err != nil {
			return nil, err
		}
		addr, err := f[0].Address()
		if err != nil {
			return nil, err
		}
		keyItems, err := f[1].Items()
		if err != nil {
			return nil, err
		}
		keys := make([]Hash, len(keyItems))
		for i, k := range keyItems {
			if keys[i], err = k.Hash(); err != nil {
				return nil, err
			}
		}
		al = append(al, AccessTuple{Address: addr, StorageKeys: keys})
	}
	return al, nil
}

// Transaction es una transacción firmada (o por firmar).
type Transaction struct {
	// Type es el formato de codificación.
	Type TxType
	// ChainID es la red para la que se firmó (anti-replay).
	ChainID ChainID
	// Nonce es el número de secuencia del remitente; evita duplicados y
	// ordena las transacciones de una misma cuenta.
	Nonce uint64
	// GasTipCap es la propina máxima por unidad de gas para el proponente
	// (maxPriorityFeePerGas). En legacy coincide con gasPrice.
	GasTipCap Amount
	// GasFeeCap es el máximo total por unidad de gas (maxFeePerGas): base
	// fee + propina nunca lo superan. En legacy coincide con gasPrice.
	GasFeeCap Amount
	// Gas es el límite de gas que el remitente está dispuesto a consumir.
	Gas uint64
	// To es el destinatario; nil significa creación de contrato.
	To *Address
	// Value es la cantidad de wei transferida.
	Value Amount
	// Data es el calldata (o el initcode si es creación).
	Data []byte
	// AccessList es la lista de accesos EIP-2930 (sólo tipo 0x02).
	AccessList AccessList
	// Sig es la firma recuperable (cero si no está firmada).
	Sig Signature

	// hash cachea Hash(); se calcula una sola vez.
	hash atomic.Pointer[Hash]
	// sender cachea el remitente recuperado por el paquete crypto.
	sender atomic.Pointer[Address]
	// size cachea el tamaño codificado.
	size atomic.Uint64
}

// NewLegacyTx crea una transacción legacy sin firmar.
func NewLegacyTx(chainID ChainID, nonce uint64, to *Address, value Amount, gas uint64, gasPrice Amount, data []byte) *Transaction {
	return &Transaction{
		Type: LegacyTxType, ChainID: chainID, Nonce: nonce, To: copyAddrPtr(to), Value: value,
		Gas: gas, GasTipCap: gasPrice, GasFeeCap: gasPrice, Data: append([]byte(nil), data...),
	}
}

// NewDynamicFeeTx crea una transacción EIP-1559 sin firmar.
func NewDynamicFeeTx(chainID ChainID, nonce uint64, to *Address, value Amount, gas uint64, tipCap, feeCap Amount, data []byte, al AccessList) *Transaction {
	return &Transaction{
		Type: DynamicFeeTxType, ChainID: chainID, Nonce: nonce, To: copyAddrPtr(to), Value: value,
		Gas: gas, GasTipCap: tipCap, GasFeeCap: feeCap, Data: append([]byte(nil), data...), AccessList: copyAccessList(al),
	}
}

// copyAddrPtr copia un *Address para que la tx no comparta memoria con el llamador.
func copyAddrPtr(a *Address) *Address {
	if a == nil {
		return nil
	}
	c := *a
	return &c
}

// copyAccessList hace una copia profunda de la access list.
func copyAccessList(al AccessList) AccessList {
	if al == nil {
		return nil
	}
	out := make(AccessList, len(al))
	for i, t := range al {
		out[i] = AccessTuple{Address: t.Address, StorageKeys: append([]Hash(nil), t.StorageKeys...)}
	}
	return out
}

// Copy devuelve una copia profunda sin cachés (ni hash ni remitente).
func (tx *Transaction) Copy() *Transaction {
	return &Transaction{
		Type: tx.Type, ChainID: tx.ChainID, Nonce: tx.Nonce, GasTipCap: tx.GasTipCap, GasFeeCap: tx.GasFeeCap,
		Gas: tx.Gas, To: copyAddrPtr(tx.To), Value: tx.Value, Data: append([]byte(nil), tx.Data...),
		AccessList: copyAccessList(tx.AccessList), Sig: tx.Sig,
	}
}

// WithSignature devuelve una copia con la firma dada.
func (tx *Transaction) WithSignature(sig Signature) *Transaction {
	c := tx.Copy()
	c.Sig = sig
	return c
}

// GasPrice devuelve el precio de gas "nominal" (GasFeeCap). Para legacy es el gasPrice.
func (tx *Transaction) GasPrice() Amount { return tx.GasFeeCap }

// IsContractCreation informa si la tx despliega un contrato.
func (tx *Transaction) IsContractCreation() bool { return tx.To == nil }

// IsSigned informa si tiene firma.
func (tx *Transaction) IsSigned() bool { return !tx.Sig.IsZero() }

// Cost devuelve el máximo que la tx puede debitar: Gas*GasFeeCap + Value.
// El mempool exige que el balance del remitente lo cubra.
func (tx *Transaction) Cost() Amount { return tx.GasFeeCap.MulUint64(tx.Gas).Add(tx.Value) }

// EffectiveGasTip devuelve la propina efectiva por gas dado un base fee:
// min(GasTipCap, GasFeeCap - baseFee). Devuelve error si GasFeeCap < baseFee
// (la tx no puede incluirse en ese bloque).
func (tx *Transaction) EffectiveGasTip(baseFee Amount) (Amount, error) {
	room, err := tx.GasFeeCap.CheckedSub(baseFee)
	if err != nil {
		return Amount{}, fmt.Errorf("fee cap %s menor que base fee %s", tx.GasFeeCap, baseFee)
	}
	return tx.GasTipCap.Min(room), nil
}

// EffectiveGasPrice devuelve lo que efectivamente se paga por gas:
// baseFee + propina efectiva (acotado por GasFeeCap).
func (tx *Transaction) EffectiveGasPrice(baseFee Amount) (Amount, error) {
	tip, err := tx.EffectiveGasTip(baseFee)
	if err != nil {
		return Amount{}, err
	}
	return baseFee.Add(tip), nil
}

// IntrinsicGas calcula el gas mínimo que consume la tx antes de ejecutar
// código: costo base + bytes de data + access list + initcode (EIP-3860).
// Devuelve error si hay desborde aritmético.
func (tx *Transaction) IntrinsicGas() (uint64, error) {
	gas := TxGas
	if tx.IsContractCreation() {
		gas = TxGasContractCreation
	}
	var nz uint64
	for _, b := range tx.Data {
		if b != 0 {
			nz++
		}
	}
	z := uint64(len(tx.Data)) - nz
	add := func(x uint64) error {
		if gas+x < gas {
			return errors.New("desborde de gas intrínseco")
		}
		gas += x
		return nil
	}
	// Multiplicaciones acotadas: len(Data) <= MaxTxSize, no desbordan.
	if err := add(nz * TxDataNonZeroGas); err != nil {
		return 0, err
	}
	if err := add(z * TxDataZeroGas); err != nil {
		return 0, err
	}
	if tx.IsContractCreation() {
		words := (uint64(len(tx.Data)) + 31) / 32
		if err := add(words * InitCodeWordGas); err != nil {
			return 0, err
		}
	}
	if err := add(uint64(len(tx.AccessList)) * TxAccessListAddressGas); err != nil {
		return 0, err
	}
	if err := add(uint64(tx.AccessList.StorageKeys()) * TxAccessListStorageKeyGas); err != nil {
		return 0, err
	}
	return gas, nil
}

// encodeTo codifica el destinatario: string vacío si es creación.
func (tx *Transaction) encodeTo() []byte {
	if tx.To == nil {
		return RLPEmptyString
	}
	return tx.To.EncodeRLP()
}

// SigningPayload devuelve los bytes que se hashean para firmar:
//   - legacy: RLP([nonce, gasPrice, gas, to, value, data, chainId, 0, 0]) (EIP-155)
//   - 0x02:   0x02 || RLP([chainId, nonce, tip, feeCap, gas, to, value, data, accessList])
func (tx *Transaction) SigningPayload() ([]byte, error) {
	switch tx.Type {
	case LegacyTxType:
		return EncodeList(
			EncodeUint(tx.Nonce), tx.GasFeeCap.EncodeRLP(), EncodeUint(tx.Gas), tx.encodeTo(),
			tx.Value.EncodeRLP(), EncodeBytes(tx.Data), EncodeUint(uint64(tx.ChainID)), EncodeUint(0), EncodeUint(0),
		), nil
	case DynamicFeeTxType:
		body := EncodeList(
			EncodeUint(uint64(tx.ChainID)), EncodeUint(tx.Nonce), tx.GasTipCap.EncodeRLP(), tx.GasFeeCap.EncodeRLP(),
			EncodeUint(tx.Gas), tx.encodeTo(), tx.Value.EncodeRLP(), EncodeBytes(tx.Data), tx.AccessList.encodeRLP(),
		)
		return append([]byte{byte(DynamicFeeTxType)}, body...), nil
	default:
		return nil, ErrTxTypeNotSupported
	}
}

// SigningHash es Keccak256(SigningPayload()): lo que firma el remitente.
func (tx *Transaction) SigningHash() (Hash, error) {
	p, err := tx.SigningPayload()
	if err != nil {
		return Hash{}, err
	}
	return Keccak256Hash(p), nil
}

// MarshalBinary devuelve la codificación canónica de red/almacenamiento.
func (tx *Transaction) MarshalBinary() ([]byte, error) {
	r, s := tx.Sig.R(), tx.Sig.S()
	switch tx.Type {
	case LegacyTxType:
		// V sólo es significativa si está firmada; sin firma se codifica 0.
		var v uint64
		if tx.IsSigned() {
			v = tx.ChainID.EIP155V(tx.Sig.V())
		}
		return EncodeList(
			EncodeUint(tx.Nonce), tx.GasFeeCap.EncodeRLP(), EncodeUint(tx.Gas), tx.encodeTo(),
			tx.Value.EncodeRLP(), EncodeBytes(tx.Data), EncodeUint(v), EncodeBig(r), EncodeBig(s),
		), nil
	case DynamicFeeTxType:
		body := EncodeList(
			EncodeUint(uint64(tx.ChainID)), EncodeUint(tx.Nonce), tx.GasTipCap.EncodeRLP(), tx.GasFeeCap.EncodeRLP(),
			EncodeUint(tx.Gas), tx.encodeTo(), tx.Value.EncodeRLP(), EncodeBytes(tx.Data), tx.AccessList.encodeRLP(),
			EncodeUint(uint64(tx.Sig.V())), EncodeBig(r), EncodeBig(s),
		)
		return append([]byte{byte(DynamicFeeTxType)}, body...), nil
	default:
		return nil, ErrTxTypeNotSupported
	}
}

// MustMarshalBinary es MarshalBinary para tipos ya validados (entra en pánico si falla).
func (tx *Transaction) MustMarshalBinary() []byte {
	b, err := tx.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return b
}

// DecodeTransaction decodifica una transacción desde su forma binaria.
// Distingue el formato por el primer byte: >= 0xc0 es una lista RLP (legacy);
// si no, es el byte de tipo del sobre EIP-2718.
func DecodeTransaction(b []byte) (*Transaction, error) {
	if len(b) == 0 {
		return nil, ErrRLPTruncated
	}
	if len(b) > MaxTxSize {
		return nil, fmt.Errorf("tx demasiado grande: %d bytes", len(b))
	}
	var tx *Transaction
	var err error
	if b[0] >= 0xc0 {
		tx, err = decodeLegacy(b)
	} else if TxType(b[0]) == DynamicFeeTxType {
		tx, err = decodeDynamic(b[1:])
	} else {
		return nil, fmt.Errorf("%w: 0x%02x", ErrTxTypeNotSupported, b[0])
	}
	if err != nil {
		return nil, err
	}
	tx.size.Store(uint64(len(b)))
	return tx, nil
}

// decodeTo decodifica el destinatario (vacío = creación).
func decodeTo(it RLPItem) (*Address, error) {
	b, err := it.Bytes()
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, nil
	}
	a, err := it.Address()
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// decodeSigParts arma la Signature a partir de V (ya normalizada), R y S.
func decodeSigParts(v uint64, rIt, sIt RLPItem) (Signature, error) {
	r, err := rIt.Big()
	if err != nil {
		return Signature{}, err
	}
	s, err := sIt.Big()
	if err != nil {
		return Signature{}, err
	}
	if v > 1 {
		return Signature{}, ErrInvalidSignature
	}
	return NewSignature(r, s, byte(v))
}

// decodeLegacy decodifica una tx legacy de 9 campos.
func decodeLegacy(b []byte) (*Transaction, error) {
	it, err := DecodeRLP(b)
	if err != nil {
		return nil, err
	}
	f, err := it.ListN(9)
	if err != nil {
		return nil, err
	}
	tx := &Transaction{Type: LegacyTxType}
	if tx.Nonce, err = f[0].Uint64(); err != nil {
		return nil, err
	}
	if tx.GasFeeCap, err = DecodeAmountRLP(f[1]); err != nil {
		return nil, err
	}
	tx.GasTipCap = tx.GasFeeCap
	if tx.Gas, err = f[2].Uint64(); err != nil {
		return nil, err
	}
	if tx.To, err = decodeTo(f[3]); err != nil {
		return nil, err
	}
	if tx.Value, err = DecodeAmountRLP(f[4]); err != nil {
		return nil, err
	}
	if tx.Data, err = f[5].BytesCopy(); err != nil {
		return nil, err
	}
	v, err := f[6].Uint64()
	if err != nil {
		return nil, err
	}
	if v == 0 {
		// Sin firmar: R y S deben ser cero; el chain id queda desconocido.
		tx.Sig, err = decodeSigParts(0, f[7], f[8])
		if err != nil {
			return nil, err
		}
		if !tx.Sig.IsZero() {
			return nil, ErrInvalidSignature
		}
		return tx, nil
	}
	cid, rec, err := ChainIDFromEIP155V(v)
	if err != nil {
		return nil, err
	}
	tx.ChainID = cid
	if tx.Sig, err = decodeSigParts(uint64(rec), f[7], f[8]); err != nil {
		return nil, err
	}
	return tx, nil
}

// decodeDynamic decodifica el cuerpo RLP (12 campos) de una tx 0x02.
func decodeDynamic(b []byte) (*Transaction, error) {
	it, err := DecodeRLP(b)
	if err != nil {
		return nil, err
	}
	f, err := it.ListN(12)
	if err != nil {
		return nil, err
	}
	tx := &Transaction{Type: DynamicFeeTxType}
	cid, err := f[0].Uint64()
	if err != nil {
		return nil, err
	}
	tx.ChainID = ChainID(cid)
	if tx.Nonce, err = f[1].Uint64(); err != nil {
		return nil, err
	}
	if tx.GasTipCap, err = DecodeAmountRLP(f[2]); err != nil {
		return nil, err
	}
	if tx.GasFeeCap, err = DecodeAmountRLP(f[3]); err != nil {
		return nil, err
	}
	if tx.Gas, err = f[4].Uint64(); err != nil {
		return nil, err
	}
	if tx.To, err = decodeTo(f[5]); err != nil {
		return nil, err
	}
	if tx.Value, err = DecodeAmountRLP(f[6]); err != nil {
		return nil, err
	}
	if tx.Data, err = f[7].BytesCopy(); err != nil {
		return nil, err
	}
	if tx.AccessList, err = decodeAccessList(f[8]); err != nil {
		return nil, err
	}
	v, err := f[9].Uint64()
	if err != nil {
		return nil, err
	}
	if tx.Sig, err = decodeSigParts(v, f[10], f[11]); err != nil {
		return nil, err
	}
	return tx, nil
}

// Hash devuelve el identificador de la tx: Keccak256 de su codificación
// binaria (cacheado). Incluye la firma, así que sólo es definitivo una vez firmada.
func (tx *Transaction) Hash() Hash {
	if h := tx.hash.Load(); h != nil {
		return *h
	}
	h := Keccak256Hash(tx.MustMarshalBinary())
	tx.hash.Store(&h)
	return h
}

// Size devuelve el tamaño codificado en bytes (cacheado).
func (tx *Transaction) Size() uint64 {
	if s := tx.size.Load(); s != 0 {
		return s
	}
	s := uint64(len(tx.MustMarshalBinary()))
	tx.size.Store(s)
	return s
}

// CachedSender devuelve el remitente si ya fue recuperado (y true), o false.
// Lo usa el paquete crypto para no repetir la costosa recuperación ECDSA.
func (tx *Transaction) CachedSender() (Address, bool) {
	if a := tx.sender.Load(); a != nil {
		return *a, true
	}
	return Address{}, false
}

// SetCachedSender guarda el remitente ya verificado. Sólo debe llamarlo
// código que efectivamente recuperó la dirección desde la firma.
func (tx *Transaction) SetCachedSender(a Address) { tx.sender.Store(&a) }

// ValidateBasic hace validaciones sin estado (no requiere balances ni
// nonces): tipo, chain id, firma en rango, tamaño de initcode, gas >=
// intrínseco y fee cap >= tip cap.
func (tx *Transaction) ValidateBasic(chainID ChainID) error {
	if tx.Type != LegacyTxType && tx.Type != DynamicFeeTxType {
		return ErrTxTypeNotSupported
	}
	if tx.ChainID != chainID {
		return newValidationError(ErrInvalidChainID, "tx", "chainId", "es %d, se esperaba %d", tx.ChainID, chainID)
	}
	if !tx.IsSigned() {
		return ErrUnsignedTx
	}
	if !tx.Sig.ValidateValues(true) {
		return newValidationError(ErrInvalidSignature, "tx", "sig", "valores R/S/V fuera de rango")
	}
	if tx.GasFeeCap.Lt(tx.GasTipCap) {
		return newValidationError(nil, "tx", "gasTipCap", "propina %s mayor que fee cap %s", tx.GasTipCap, tx.GasFeeCap)
	}
	if tx.IsContractCreation() && len(tx.Data) > MaxInitCodeSize {
		return newValidationError(nil, "tx", "data", "initcode de %d bytes supera %d", len(tx.Data), MaxInitCodeSize)
	}
	ig, err := tx.IntrinsicGas()
	if err != nil {
		return err
	}
	if tx.Gas < ig {
		return newValidationError(nil, "tx", "gas", "límite %d menor que gas intrínseco %d", tx.Gas, ig)
	}
	if tx.Size() > MaxTxSize {
		return newValidationError(nil, "tx", "size", "%d bytes supera %d", tx.Size(), MaxTxSize)
	}
	return nil
}

// Transactions es una lista de transacciones; implementa DerivableList para
// calcular la raíz de transacciones de un bloque.
type Transactions []*Transaction

// Len implementa DerivableList.
func (txs Transactions) Len() int { return len(txs) }

// EncodeIndex implementa DerivableList: valor del trie para la tx i.
func (txs Transactions) EncodeIndex(i int) []byte { return txs[i].MustMarshalBinary() }

// Hashes devuelve los hashes de todas las transacciones en orden.
func (txs Transactions) Hashes() []Hash {
	out := make([]Hash, len(txs))
	for i, tx := range txs {
		out[i] = tx.Hash()
	}
	return out
}
