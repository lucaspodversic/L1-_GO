package types

// Constantes globales del protocolo. Reunirlas en un solo lugar evita "números
// mágicos" dispersos y deja claro qué parámetros son de consenso (cambiarlos
// produce un hard fork) y cuáles son simples límites de implementación.

const (
	// HashLength es el largo en bytes de un hash Keccak-256.
	HashLength = 32
	// AddressLength es el largo en bytes de una dirección (últimos 20 bytes
	// del Keccak-256 de la clave pública, como en Ethereum).
	AddressLength = 20
	// SignatureLength es el largo de una firma secp256k1 recuperable: R(32) || S(32) || V(1).
	SignatureLength = 65
	// BloomByteLength es el tamaño del filtro Bloom de logs (2048 bits).
	BloomByteLength = 256
	// BloomBitLength es el tamaño del Bloom en bits.
	BloomBitLength = 8 * BloomByteLength
)

// Unidades de valor. La unidad mínima es el "wei" (heredado de Ethereum);
// la moneda nativa tiene 18 decimales.
const (
	// Wei es la unidad indivisible.
	Wei uint64 = 1
	// GWei = 10^9 wei, unidad habitual para precios de gas.
	GWei uint64 = 1_000_000_000
	// Ether = 10^18 wei; representa una unidad "entera" de la moneda nativa.
	Ether uint64 = 1_000_000_000_000_000_000
	// Decimals es la cantidad de decimales de la moneda nativa.
	Decimals = 18
)

// Parámetros de gas intrínseco (de consenso). Siguen los valores de Ethereum
// post-Istanbul/Shanghai para que los contratos y herramientas se comporten igual.
const (
	// TxGas es el costo base de toda transacción que no crea contrato.
	TxGas uint64 = 21_000
	// TxGasContractCreation es el costo base de una transacción de creación.
	TxGasContractCreation uint64 = 53_000
	// TxDataZeroGas es el costo por byte cero en el campo data.
	TxDataZeroGas uint64 = 4
	// TxDataNonZeroGas es el costo por byte distinto de cero (EIP-2028).
	TxDataNonZeroGas uint64 = 16
	// TxAccessListAddressGas es el costo por dirección en la access list (EIP-2930).
	TxAccessListAddressGas uint64 = 2_400
	// TxAccessListStorageKeyGas es el costo por slot en la access list.
	TxAccessListStorageKeyGas uint64 = 1_900
	// InitCodeWordGas es el costo por palabra de 32 bytes del initcode (EIP-3860).
	InitCodeWordGas uint64 = 2
	// MaxCodeSize es el tamaño máximo de código desplegado (EIP-170).
	MaxCodeSize = 24_576
	// MaxInitCodeSize es el tamaño máximo del initcode (EIP-3860).
	MaxInitCodeSize = 2 * MaxCodeSize
)

// Parámetros del mercado de comisiones (EIP-1559) y de bloques.
const (
	// InitialBaseFee es el base fee del bloque génesis por defecto (1 gwei).
	InitialBaseFee uint64 = 1_000_000_000
	// BaseFeeChangeDenominator limita la variación del base fee por bloque a 1/8.
	BaseFeeChangeDenominator uint64 = 8
	// ElasticityMultiplier: el objetivo de gas es GasLimit / 2.
	ElasticityMultiplier uint64 = 2
	// MinBaseFee es un piso para que el base fee nunca llegue a 0 (protección anti-spam).
	MinBaseFee uint64 = 7
	// DefaultGasLimit es el límite de gas por bloque por defecto.
	DefaultGasLimit uint64 = 30_000_000
	// MinGasLimit es el mínimo admitido para el límite de gas de un bloque.
	MinGasLimit uint64 = 5_000
	// MaxGasLimit es el máximo admitido (2^63-1) para evitar desbordes.
	MaxGasLimit uint64 = 1<<63 - 1
	// GasLimitBoundDivisor limita cuánto puede cambiar el GasLimit entre bloques (1/1024).
	GasLimitBoundDivisor uint64 = 1024
	// MaxExtraDataSize es el tamaño máximo del campo ExtraData de la cabecera.
	MaxExtraDataSize = 64
)

// Límites de implementación (no de consenso estricto, pero conviene que todos
// los nodos los compartan para no propagar basura).
const (
	// MaxTxSize es el tamaño máximo de una transacción codificada (128 KiB).
	MaxTxSize = 128 * 1024
	// MaxBlockSize es el tamaño máximo de un bloque codificado (10 MiB).
	MaxBlockSize = 10 * 1024 * 1024
	// MaxJustifySize acota el tamaño del QC opaco dentro del bloque.
	MaxJustifySize = 64 * 1024
	// MaxRLPDepth es la profundidad máxima de anidamiento que acepta el decodificador RLP.
	MaxRLPDepth = 64
)

// Parámetros de consenso por defecto (se pueden sobreescribir en el génesis).
const (
	// DefaultEpochLength es la cantidad de bloques por época (rotación de validadores).
	DefaultEpochLength uint64 = 1_000
	// DefaultBlockTimeMs es el tiempo objetivo entre bloques en milisegundos.
	DefaultBlockTimeMs uint64 = 2_000
	// DefaultViewTimeoutMs es el timeout base de una vista antes de un view-change.
	DefaultViewTimeoutMs uint64 = 6_000
	// DefaultMaxValidators es la cantidad máxima de validadores activos.
	DefaultMaxValidators = 100
)
