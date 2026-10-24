package types

// Este archivo define Genesis, la especificación del bloque 0: parámetros de
// la cadena, saldos y contratos iniciales (alloc) y el conjunto inicial de
// validadores. Se carga desde JSON (archivo genesis.json) y todos los nodos de
// una red deben usar exactamente el mismo: su hash determina la identidad de
// la cadena.
//
// Aquí sólo hay datos y validación. Aplicar el alloc al estado y escribir el
// bloque 0 en la base es trabajo de storage (genesis_state.go), porque
// requiere el trie de estado.

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// ConsensusParams son los parámetros del consenso BFT fijados en el génesis.
type ConsensusParams struct {
	// EpochLength es la cantidad de bloques por época.
	EpochLength uint64 `json:"epochLength"`
	// BlockTimeMs es el intervalo objetivo entre bloques.
	BlockTimeMs uint64 `json:"blockTimeMs"`
	// ViewTimeoutMs es el timeout base de una vista.
	ViewTimeoutMs uint64 `json:"viewTimeoutMs"`
	// MaxValidators es el tamaño máximo del conjunto activo.
	MaxValidators int `json:"maxValidators"`
	// MinStake es el stake mínimo para ser validador.
	MinStake Amount `json:"minStake"`
}

// DefaultConsensusParams devuelve parámetros razonables para devnet/testnet.
func DefaultConsensusParams() ConsensusParams {
	return ConsensusParams{
		EpochLength: DefaultEpochLength, BlockTimeMs: DefaultBlockTimeMs,
		ViewTimeoutMs: DefaultViewTimeoutMs, MaxValidators: DefaultMaxValidators,
		MinStake: EtherAmount(1),
	}
}

// GenesisAccount es el estado inicial de una cuenta.
type GenesisAccount struct {
	// Balance inicial en wei (acepta decimal, hex o "10ether").
	Balance Amount `json:"balance"`
	// Nonce inicial (normalmente 0; 1 para contratos según EIP-161).
	Nonce uint64 `json:"nonce,omitempty"`
	// Code es el bytecode desplegado (contratos de sistema).
	Code HexBytes `json:"code,omitempty"`
	// Storage son los slots iniciales del contrato.
	Storage map[Hash]Hash `json:"storage,omitempty"`
}

// GenesisValidator es un validador inicial.
type GenesisValidator struct {
	// Address es la cuenta del validador (recibe recompensas).
	Address Address `json:"address"`
	// BLSPubKey es la clave pública BLS12-381 comprimida (48 bytes) con la
	// que firma votos agregables.
	BLSPubKey HexBytes `json:"blsPubKey"`
	// ProofOfPossession es la firma BLS de su propia clave pública (96
	// bytes); evita ataques de "rogue key" en la agregación. Opcional en
	// devnet, la verifica el paquete consensus si está presente.
	ProofOfPossession HexBytes `json:"pop,omitempty"`
	// Power es el peso de voto (stake efectivo).
	Power uint64 `json:"power"`
}

// EncodeRLP codifica [address, blsPubKey, power] (el PoP no se compromete
// en el hash del conjunto: sólo sirve para validar el alta).
func (v GenesisValidator) EncodeRLP() []byte {
	return EncodeList(v.Address.EncodeRLP(), EncodeBytes(v.BLSPubKey), EncodeUint(v.Power))
}

// HashValidators calcula el ValidatorsHash de un conjunto: Keccak256 de la
// lista RLP de validadores ordenados por dirección. El paquete consensus usa
// la misma función para que génesis y épocas posteriores sean coherentes.
func HashValidators(vals []GenesisValidator) Hash {
	sorted := append([]GenesisValidator(nil), vals...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Address.Cmp(sorted[j].Address) < 0 })
	items := make([][]byte, len(sorted))
	for i, v := range sorted {
		items[i] = v.EncodeRLP()
	}
	return Keccak256Hash(EncodeList(items...))
}

// Genesis es la especificación completa del bloque 0.
type Genesis struct {
	// ChainID identifica la red.
	ChainID ChainID `json:"chainId"`
	// Timestamp del bloque génesis (segundos Unix).
	Timestamp uint64 `json:"timestamp"`
	// GasLimit inicial por bloque.
	GasLimit uint64 `json:"gasLimit"`
	// BaseFee inicial (EIP-1559).
	BaseFee Amount `json:"baseFee"`
	// ExtraData libre (p. ej. un mensaje fundacional).
	ExtraData HexBytes `json:"extraData,omitempty"`
	// Consensus son los parámetros del consenso.
	Consensus ConsensusParams `json:"consensus"`
	// Alloc es el estado inicial por dirección.
	Alloc map[Address]GenesisAccount `json:"alloc"`
	// Validators es el conjunto inicial de validadores.
	Validators []GenesisValidator `json:"validators"`
}

// DefaultDevGenesis devuelve un génesis de desarrollo con un único
// validador y una cuenta con fondos. Útil para tests y "init --dev".
func DefaultDevGenesis(funded Address, validator GenesisValidator) *Genesis {
	return &Genesis{
		ChainID: DevnetChainID, GasLimit: DefaultGasLimit, BaseFee: NewAmount(InitialBaseFee),
		Consensus:  DefaultConsensusParams(),
		Alloc:      map[Address]GenesisAccount{funded: {Balance: EtherAmount(1_000_000)}},
		Validators: []GenesisValidator{validator},
	}
}

// LoadGenesis lee y valida un génesis desde un archivo JSON.
func LoadGenesis(path string) (*Genesis, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseGenesis(data)
}

// ParseGenesis decodifica y valida un génesis JSON. Los campos de consenso
// ausentes toman valores por defecto.
func ParseGenesis(data []byte) (*Genesis, error) {
	g := &Genesis{Consensus: DefaultConsensusParams()}
	if err := json.Unmarshal(data, g); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidGenesis, err)
	}
	if g.GasLimit == 0 {
		g.GasLimit = DefaultGasLimit
	}
	if g.BaseFee.IsZero() {
		g.BaseFee = NewAmount(InitialBaseFee)
	}
	return g, g.Validate()
}

// Save escribe el génesis como JSON indentado.
func (g *Genesis) Save(path string) error {
	data, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// Validate comprueba la coherencia del génesis.
func (g *Genesis) Validate() error {
	if err := g.ChainID.Validate(); err != nil {
		return newValidationError(ErrInvalidGenesis, "genesis", "chainId", "%v", err)
	}
	if g.GasLimit < MinGasLimit || g.GasLimit > MaxGasLimit {
		return newValidationError(ErrInvalidGenesis, "genesis", "gasLimit", "%d fuera de rango", g.GasLimit)
	}
	if len(g.ExtraData) > MaxExtraDataSize {
		return newValidationError(ErrInvalidGenesis, "genesis", "extraData", "demasiado largo")
	}
	c := g.Consensus
	if c.EpochLength == 0 || c.BlockTimeMs == 0 || c.ViewTimeoutMs == 0 || c.MaxValidators <= 0 {
		return newValidationError(ErrInvalidGenesis, "genesis", "consensus", "parámetros en cero")
	}
	if len(g.Validators) == 0 {
		return newValidationError(ErrInvalidGenesis, "genesis", "validators", "se requiere al menos un validador")
	}
	if len(g.Validators) > c.MaxValidators {
		return newValidationError(ErrInvalidGenesis, "genesis", "validators", "%d supera el máximo %d", len(g.Validators), c.MaxValidators)
	}
	seen := make(map[Address]bool)
	for i, v := range g.Validators {
		if seen[v.Address] {
			return newValidationError(ErrInvalidGenesis, "genesis", "validators", "dirección duplicada %s", v.Address)
		}
		seen[v.Address] = true
		if len(v.BLSPubKey) != SchemeBLS12381.PublicKeySize() {
			return newValidationError(ErrInvalidGenesis, "genesis", "validators", "validador %d: clave BLS de %d bytes", i, len(v.BLSPubKey))
		}
		if len(v.ProofOfPossession) != 0 && len(v.ProofOfPossession) != SchemeBLS12381.SignatureSize() {
			return newValidationError(ErrInvalidGenesis, "genesis", "validators", "validador %d: PoP de %d bytes", i, len(v.ProofOfPossession))
		}
		if v.Power == 0 {
			return newValidationError(ErrInvalidGenesis, "genesis", "validators", "validador %d con poder 0", i)
		}
	}
	for addr, acc := range g.Alloc {
		if len(acc.Code) > MaxCodeSize {
			return newValidationError(ErrInvalidGenesis, "genesis", "alloc", "código de %s supera %d bytes", addr, MaxCodeSize)
		}
	}
	return nil
}

// ValidatorsHash devuelve el compromiso del conjunto inicial.
func (g *Genesis) ValidatorsHash() Hash { return HashValidators(g.Validators) }

// SortedAllocAddresses devuelve las direcciones del alloc ordenadas, para
// aplicar el estado de forma determinista.
func (g *Genesis) SortedAllocAddresses() []Address {
	out := make([]Address, 0, len(g.Alloc))
	for a := range g.Alloc {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Cmp(out[j]) < 0 })
	return out
}

// ToHeader construye la cabecera del bloque 0 dado el StateRoot ya calculado
// a partir del alloc. TxRoot y ReceiptRoot son los de un trie vacío.
func (g *Genesis) ToHeader(stateRoot Hash) *Header {
	return &Header{
		Number: 0, Timestamp: g.Timestamp, StateRoot: stateRoot, TxRoot: EmptyRootHash, ReceiptRoot: EmptyRootHash,
		GasLimit: g.GasLimit, BaseFee: g.BaseFee, ExtraData: append(HexBytes(nil), g.ExtraData...),
		Epoch: 0, View: 0, ValidatorsHash: g.ValidatorsHash(),
		// La aleatoriedad inicial se deriva del propio génesis, determinista.
		Random: Keccak256Hash([]byte("l1-genesis-random"), EncodeUint(uint64(g.ChainID))),
	}
}

// ToBlock construye el bloque 0 (sin transacciones ni QC).
func (g *Genesis) ToBlock(stateRoot Hash) *Block { return NewBlock(g.ToHeader(stateRoot), nil, nil) }
