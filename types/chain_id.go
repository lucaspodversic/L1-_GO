package types

// Este archivo define ChainID, el identificador numérico de la red. Va dentro
// de cada transacción firmada (EIP-155 / EIP-1559) para que una firma válida
// en una red no pueda "reproducirse" en otra (protección anti-replay), y
// también se usa en el handshake P2P para no conectar nodos de redes distintas.

import (
	"fmt"
	"math/big"
	"strconv"
)

// ChainID identifica una red (mainnet, testnet, devnet...).
type ChainID uint64

// Identificadores predefinidos. Son valores arbitrarios elegidos para no
// colisionar con redes EVM conocidas.
const (
	// MainnetChainID es la red principal.
	MainnetChainID ChainID = 7771
	// TestnetChainID es la red de pruebas pública.
	TestnetChainID ChainID = 7772
	// DevnetChainID es la red local de desarrollo (mismo valor que el típico
	// de Hardhat/Ganache para que las wallets la reconozcan).
	DevnetChainID ChainID = 1337
)

// Validate rechaza el 0 (sin protección anti-replay) y valores tan grandes
// que la V de EIP-155 (chainID*2+36) desbordaría 64 bits.
func (c ChainID) Validate() error {
	if c == 0 {
		return fmt.Errorf("%w: no puede ser 0", ErrInvalidChainID)
	}
	if uint64(c) > (1<<63-36)/2 {
		return fmt.Errorf("%w: demasiado grande", ErrInvalidChainID)
	}
	return nil
}

// Uint64 devuelve el valor numérico.
func (c ChainID) Uint64() uint64 { return uint64(c) }

// Big devuelve el valor como *big.Int (útil para la EVM, opcode CHAINID).
func (c ChainID) Big() *big.Int { return new(big.Int).SetUint64(uint64(c)) }

// Name devuelve un nombre legible si es una red conocida.
func (c ChainID) Name() string {
	switch c {
	case MainnetChainID:
		return "mainnet"
	case TestnetChainID:
		return "testnet"
	case DevnetChainID:
		return "devnet"
	default:
		return "custom"
	}
}

// String implementa fmt.Stringer ("1337 (devnet)").
func (c ChainID) String() string { return strconv.FormatUint(uint64(c), 10) + " (" + c.Name() + ")" }

// ParseChainID parsea un chain id en decimal, hexadecimal o por nombre.
func ParseChainID(s string) (ChainID, error) {
	switch s {
	case "mainnet":
		return MainnetChainID, nil
	case "testnet":
		return TestnetChainID, nil
	case "devnet":
		return DevnetChainID, nil
	}
	v, err := ParseUint64(s)
	if err != nil {
		return 0, fmt.Errorf("%w: %q", ErrInvalidChainID, s)
	}
	c := ChainID(v)
	return c, c.Validate()
}

// EIP155V calcula la V de una firma legacy: recID + chainID*2 + 35.
func (c ChainID) EIP155V(recID byte) uint64 { return uint64(recID) + uint64(c)*2 + 35 }

// ChainIDFromEIP155V deduce chainID y recovery id a partir de una V legacy.
// Las V pre-EIP-155 (27/28) se rechazan: no tienen protección anti-replay.
func ChainIDFromEIP155V(v uint64) (ChainID, byte, error) {
	if v < 37 {
		return 0, 0, fmt.Errorf("%w: V=%d no es EIP-155", ErrInvalidSignature, v)
	}
	rec := byte((v - 35) % 2)
	return ChainID((v - 35) / 2), rec, nil
}
