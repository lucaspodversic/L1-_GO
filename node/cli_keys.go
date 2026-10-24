package node

// Subcomando keys: generar e inspeccionar claves.

import (
	"crypto/rand"
	"fmt"
	"os"

	"github.com/l1/l1/consensus"
	"github.com/l1/l1/crypto"
	"github.com/l1/l1/types"
)

func cmdKeys(args []string) error {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "uso: l1 keys <new-secp|new-ed25519|new-validator|inspect> ...")
		return fmt.Errorf("falta subcomando")
	}
	switch args[0] {
	case "new-secp":
		return keysNewSecp(args[1:])
	case "new-ed25519":
		return keysNewEd(args[1:])
	case "new-validator":
		return keysNewVal(args[1:])
	case "inspect":
		return keysInspect(args[1:])
	default:
		return fmt.Errorf("keys: subcomando desconocido %s", args[0])
	}
}

func keysNewSecp(args []string) error {
	path, pass := "", ""
	if len(args) > 0 {
		path = args[0]
	}
	if len(args) > 1 {
		pass = args[1]
	}
	sk, err := crypto.GenerateSecp256k1(rand.Reader)
	if err != nil {
		return err
	}
	if path == "" {
		fmt.Println(sk.Address().Hex())
		return nil
	}
	if err := crypto.SaveKeyFile(path, sk, pass, keyScryptN(pass)); err != nil {
		return err
	}
	fmt.Println(sk.Address().Hex(), "->", path)
	return nil
}

func keysNewEd(args []string) error {
	path, pass := "", ""
	if len(args) > 0 {
		path = args[0]
	}
	if len(args) > 1 {
		pass = args[1]
	}
	sk, err := crypto.GenerateEd25519(rand.Reader)
	if err != nil {
		return err
	}
	id := sk.PublicKey().ID()
	if path == "" {
		fmt.Println(id.Hex())
		return nil
	}
	if err := crypto.SaveKeyFile(path, sk, pass, keyScryptN(pass)); err != nil {
		return err
	}
	fmt.Println(id.Hex(), "->", path)
	return nil
}

func keysNewVal(args []string) error {
	path, pass := "", ""
	addr := types.Address{}
	if len(args) > 0 {
		path = args[0]
	}
	if len(args) > 1 {
		a, err := types.HexToAddress(args[1])
		if err != nil {
			return err
		}
		addr = a
	}
	if len(args) > 2 {
		pass = args[2]
	}
	if addr == (types.Address{}) {
		sk, err := crypto.GenerateSecp256k1(rand.Reader)
		if err != nil {
			return err
		}
		addr = sk.Address()
	}
	vk, err := consensus.GenerateValidatorKey(addr, nil)
	if err != nil {
		return err
	}
	if path != "" {
		if err := consensus.SaveValidatorKey(path, vk, pass, keyScryptN(pass)); err != nil {
			return err
		}
	}
	fmt.Println(vk.Address.Hex(), "bls", fmt.Sprintf("%x", vk.PublicKey().Bytes()[:8]), "->", path)
	return nil
}

func keysInspect(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("uso: l1 keys inspect <path> [password]")
	}
	pass := ""
	if len(args) > 1 {
		pass = args[1]
	}
	// Intentar validador primero.
	if vk, err := consensus.LoadValidatorKey(args[0], pass); err == nil {
		fmt.Println("validator", vk.Address.Hex())
		return nil
	}
	priv, err := crypto.LoadKeyFile(args[0], pass)
	if err != nil {
		return err
	}
	switch k := priv.(type) {
	case *crypto.Secp256k1PrivateKey:
		fmt.Println("secp256k1", k.Address().Hex())
	case *crypto.Ed25519PrivateKey:
		fmt.Println("ed25519", k.PublicKey().ID().Hex())
	default:
		fmt.Println("clave", priv.Scheme())
	}
	return nil
}
