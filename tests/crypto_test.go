package tests

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/l1/l1/crypto"
)

func TestCryptoSecpSignVerify(t *testing.T) {
	sk, err := crypto.GenerateSecp256k1(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	msg := crypto.Keccak256([]byte("l1-tests"))
	sig, err := sk.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !sk.PublicKey().Verify(msg, sig) {
		t.Fatal("verify")
	}
	if sk.Address().IsZero() {
		t.Fatal("addr")
	}
}

func TestCryptoEd25519AndKeccak(t *testing.T) {
	sk, err := crypto.GenerateEd25519(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("hola")
	sig, err := sk.Sign(msg)
	if err != nil || !sk.PublicKey().Verify(msg, sig) {
		t.Fatal(err)
	}
	h := crypto.Keccak256([]byte("abc"))
	if len(h) != 32 || bytes.Equal(h, make([]byte, 32)) {
		t.Fatal("keccak")
	}
}

func TestCryptoKeystoreRoundtrip(t *testing.T) {
	sk, _ := crypto.GenerateSecp256k1(rand.Reader)
	path := t.TempDir() + "/k.key"
	if err := crypto.SaveKeyFile(path, sk, "pass", crypto.LightScryptN); err != nil {
		t.Fatal(err)
	}
	got, err := crypto.LoadKeyFile(path, "pass")
	if err != nil {
		t.Fatal(err)
	}
	if got.(*crypto.Secp256k1PrivateKey).Address() != sk.Address() {
		t.Fatal("addr mismatch")
	}
}
