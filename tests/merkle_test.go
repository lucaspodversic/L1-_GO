package tests

import (
	"testing"

	"github.com/l1/l1/crypto"
)

func TestMerkleEmptyAndProof(t *testing.T) {
	h := crypto.KeccakHasher{}
	_ = crypto.MerkleEmptyRoot(h)
	leaves := [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d")}
	tree := crypto.NewMerkleTree(h, leaves)
	root := tree.Root()
	proof, err := tree.Prove(1)
	if err != nil {
		t.Fatal(err)
	}
	if !proof.Verify(root, leaves[1]) {
		t.Fatal("proof inválida")
	}
}
