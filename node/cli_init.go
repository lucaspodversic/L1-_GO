package node

// Subcomando init: prepara datadir, claves y génesis.

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"

	"github.com/l1/l1/consensus"
	"github.com/l1/l1/crypto"
	"github.com/l1/l1/storage"
	"github.com/l1/l1/types"
)

func keyScryptN(pass string) int {
	if pass == "" {
		return crypto.LightScryptN
	}
	return crypto.StandardScryptN
}

func cmdInit(args []string) error {
	cfg := DefaultConfig()
	fs := RegisterFlags("init", &cfg)
	var (
		pass  string
		dev   bool
		force bool
	)
	fs.StringVar(&pass, "password", "", "passphrase de las claves")
	fs.BoolVar(&dev, "dev", true, "génesis de desarrollo de un validador")
	fs.BoolVar(&force, "force", false, "sobrescribe génesis si ya existe")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return err
	}
	nodeKeyPath := cfg.NodeKey
	if nodeKeyPath == "" {
		nodeKeyPath = filepath.Join(cfg.DataDir, "nodekey")
	}
	valKeyPath := cfg.ValidatorKey
	if valKeyPath == "" {
		valKeyPath = filepath.Join(cfg.DataDir, "validator.key")
	}
	fundedPath := filepath.Join(cfg.DataDir, "funded.key")

	// Clave P2P Ed25519.
	if _, err := os.Stat(nodeKeyPath); err != nil {
		id, err := crypto.GenerateEd25519(rand.Reader)
		if err != nil {
			return err
		}
		if err := crypto.SaveKeyFile(nodeKeyPath, id, pass, keyScryptN(pass)); err != nil {
			return err
		}
		fmt.Println("nodekey:", nodeKeyPath)
	}

	// Cuenta funded secp256k1.
	var fundedAddr types.Address
	if _, err := os.Stat(fundedPath); err != nil {
		sk, err := crypto.GenerateSecp256k1(rand.Reader)
		if err != nil {
			return err
		}
		if err := crypto.SaveKeyFile(fundedPath, sk, pass, keyScryptN(pass)); err != nil {
			return err
		}
		fundedAddr = sk.Address()
		fmt.Println("funded:", fundedAddr.Hex(), "->", fundedPath)
	} else {
		priv, err := crypto.LoadKeyFile(fundedPath, pass)
		if err != nil {
			return err
		}
		fundedAddr = priv.(*crypto.Secp256k1PrivateKey).Address()
	}

	// Validador BLS (dirección = funded para simplicidad en --dev).
	var vk *consensus.ValidatorKey
	if _, err := os.Stat(valKeyPath); err != nil {
		var err2 error
		vk, err2 = consensus.GenerateValidatorKey(fundedAddr, nil)
		if err2 != nil {
			return err2
		}
		if err := consensus.SaveValidatorKey(valKeyPath, vk, pass, keyScryptN(pass)); err != nil {
			return err
		}
		fmt.Println("validator:", vk.Address.Hex(), "->", valKeyPath)
	} else {
		var err error
		vk, err = consensus.LoadValidatorKey(valKeyPath, pass)
		if err != nil {
			return err
		}
	}

	genesisPath := cfg.GenesisFile
	if genesisPath == "" {
		genesisPath = filepath.Join(cfg.DataDir, "genesis.json")
	}
	var gspec *types.Genesis
	if _, err := os.Stat(genesisPath); err == nil && !force {
		gspec, err = types.LoadGenesis(genesisPath)
		if err != nil {
			return err
		}
	} else {
		gv, err := consensus.GenesisValidatorFromKey(vk, 1)
		if err != nil {
			return err
		}
		if !dev && cfg.GenesisFile != "" {
			gspec, err = types.LoadGenesis(cfg.GenesisFile)
			if err != nil {
				return err
			}
		} else {
			gspec = types.DefaultDevGenesis(fundedAddr, gv)
			gspec.Consensus.EpochLength = 1_000_000
		}
		if err := gspec.Save(genesisPath); err != nil {
			return err
		}
		fmt.Println("genesis:", genesisPath)
	}

	db, err := storage.Open(storage.DefaultConfig(filepath.Join(cfg.DataDir, "chain")))
	if err != nil {
		return err
	}
	defer db.Close()
	block, err := storage.CommitGenesis(gspec, db.State, db.Blocks)
	if err != nil {
		return err
	}
	cfg.GenesisFile = genesisPath
	cfg.NodeKey = nodeKeyPath
	cfg.ValidatorKey = valKeyPath
	if err := SaveConfigFile(filepath.Join(cfg.DataDir, "config.json"), cfg); err != nil {
		return err
	}
	fmt.Printf("inicializado: genesis=%s height=0 datadir=%s\n", block.Hash().Hex(), cfg.DataDir)
	return nil
}
