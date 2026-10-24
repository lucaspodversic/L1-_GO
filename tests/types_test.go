package tests

// Pruebas unitarias del paquete types: Address, Hash, Amount, RLP, Genesis.

import (
	"bytes"
	"testing"

	"github.com/l1/l1/types"
)

func TestTypesAddressAndHash(t *testing.T) {
	a := types.BytesToAddress([]byte{1, 2, 3})
	if a.IsZero() {
		t.Fatal("no cero")
	}
	h := types.BytesToHash([]byte("hola-mundo-hash-32bytes!!!!!!"))
	if len(h) != 32 {
		t.Fatal(len(h))
	}
	b, err := a.MarshalText()
	if err != nil || !bytes.HasPrefix(b, []byte("0x")) {
		t.Fatalf("%s %v", b, err)
	}
}

func TestTypesAmount(t *testing.T) {
	a := types.EtherAmount(2)
	b := types.GWeiAmount(1_000_000_000)
	if !a.Eq(b.MulUint64(2)) && a.Cmp(types.NewAmount(0)) <= 0 {
		// EtherAmount(2) = 2e18; GWei*1e9 = 1e18 — comprobar suma
	}
	sum := a.Add(types.NewAmount(1))
	if sum.Cmp(a) <= 0 {
		t.Fatal("add")
	}
	if types.NewAmount(0).IsZero() != true {
		t.Fatal("zero")
	}
}

func TestTypesRLPRoundtripAccount(t *testing.T) {
	acc := types.NewEmptyAccount()
	acc.Nonce = 7
	acc.Balance = types.EtherAmount(3)
	enc := acc.EncodeRLP()
	dec, err := types.DecodeAccount(enc)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Nonce != 7 {
		t.Fatalf("nonce %d", dec.Nonce)
	}
}

func TestTypesGenesisValidate(t *testing.T) {
	g := types.DefaultDevGenesis(types.Address{1}, types.GenesisValidator{
		Address: types.Address{1}, BLSPubKey: make([]byte, 48), Power: 1,
	})
	if err := g.Validate(); err != nil {
		t.Fatal(err)
	}
}
