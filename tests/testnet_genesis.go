package tests

// Generador de génesis de testnet (4 validadores deterministas).

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/l1/l1/consensus"
	"github.com/l1/l1/crypto"
	"github.com/l1/l1/types"
)

// WriteTestnetGenesis genera genesis.json y claves en dir.
// Usa RNG determinista a partir de una semilla fija para reproducibilidad.
func WriteTestnetGenesis(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	const n = 4
	alloc := map[types.Address]types.GenesisAccount{}
	vals := make([]types.GenesisValidator, 0, n)
	for i := 0; i < n; i++ {
		seed := crypto.NewDeterministicRNGFrom("l1-testnet", []byte{byte(i)})
		sk, err := crypto.GenerateSecp256k1(seed)
		if err != nil {
			return err
		}
		addr := sk.Address()
		vk, err := consensus.GenerateValidatorKey(addr, seed)
		if err != nil {
			return err
		}
		gv, err := consensus.GenesisValidatorFromKey(vk, 1)
		if err != nil {
			return err
		}
		vals = append(vals, gv)
		alloc[addr] = types.GenesisAccount{Balance: types.EtherAmount(1_000_000)}
		if err := crypto.SaveKeyFile(filepath.Join(dir, fmt.Sprintf("node%d.key", i)), sk, "", crypto.LightScryptN); err != nil {
			return err
		}
		if err := consensus.SaveValidatorKey(filepath.Join(dir, fmt.Sprintf("validator%d.key", i)), vk, "", crypto.LightScryptN); err != nil {
			return err
		}
	}
	g := &types.Genesis{
		ChainID:    types.ChainID(1337),
		GasLimit:   types.DefaultGasLimit,
		BaseFee:    types.NewAmount(types.InitialBaseFee),
		Consensus:  types.DefaultConsensusParams(),
		Alloc:      alloc,
		Validators: vals,
		ExtraData:  []byte("l1-testnet"),
	}
	g.Consensus.BlockTimeMs = 500
	return g.Save(filepath.Join(dir, "genesis.json"))
}
