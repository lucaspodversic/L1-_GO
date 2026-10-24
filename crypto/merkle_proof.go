package crypto

// Pruebas de inclusión para MerkleTree. Una prueba contiene el índice de la
// hoja, el número total de hojas y los hashes hermanos de abajo a arriba.
// Conocer Total permite al verificador saber en qué niveles el nodo fue
// promovido (sin hermano), así que la prueba es mínima.

import (
	"errors"

	"github.com/l1/l1/types"
)

// Errores de pruebas de Merkle.
var (
	// ErrMerkleIndex indica un índice de hoja fuera de rango.
	ErrMerkleIndex = errors.New("crypto: índice de hoja merkle fuera de rango")
	// ErrMerkleProof indica una prueba malformada o que no verifica.
	ErrMerkleProof = errors.New("crypto: prueba merkle inválida")
)

// MerkleProof es una prueba de inclusión de una hoja.
type MerkleProof struct {
	// Algo es la función de hash con la que se construyó el árbol.
	Algo HashAlgo
	// Index es la posición de la hoja (desde 0).
	Index uint64
	// Total es el número de hojas del árbol.
	Total uint64
	// Siblings son los hashes hermanos, desde las hojas hacia la raíz.
	Siblings [][32]byte
}

// expectedSiblings calcula cuántos hermanos debe tener una prueba válida
// para (index, total), recorriendo los niveles como lo hace Prove.
func expectedSiblings(index, total uint64) int {
	n := 0
	for size := total; size > 1; size = (size + 1) / 2 {
		if index^1 < size {
			n++
		}
		index /= 2
	}
	return n
}

// ComputeRoot recalcula la raíz a partir del hash de hoja.
func (p *MerkleProof) ComputeRoot(leafHash [32]byte) ([32]byte, error) {
	h, err := HasherFor(p.Algo)
	if err != nil {
		return [32]byte{}, err
	}
	if p.Index >= p.Total || len(p.Siblings) != expectedSiblings(p.Index, p.Total) {
		return [32]byte{}, ErrMerkleProof
	}
	cur, idx, k := leafHash, p.Index, 0
	for size := p.Total; size > 1; size = (size + 1) / 2 {
		sib := idx ^ 1
		if sib < size {
			if idx&1 == 0 {
				cur = MerkleNodeHash(h, cur, p.Siblings[k]) // somos el hijo izquierdo
			} else {
				cur = MerkleNodeHash(h, p.Siblings[k], cur) // somos el hijo derecho
			}
			k++
		}
		idx /= 2
	}
	return cur, nil
}

// VerifyLeafHash comprueba que leafHash está en el árbol de raíz root.
func (p *MerkleProof) VerifyLeafHash(root, leafHash [32]byte) bool {
	got, err := p.ComputeRoot(leafHash)
	return err == nil && got == root
}

// Verify comprueba que data (sin hashear) está en el árbol de raíz root.
func (p *MerkleProof) Verify(root [32]byte, data []byte) bool {
	h, err := HasherFor(p.Algo)
	if err != nil {
		return false
	}
	return p.VerifyLeafHash(root, MerkleLeafHash(h, data))
}

// EncodeRLP serializa la prueba como [algo, index, total, [s0, s1, ...]].
func (p *MerkleProof) EncodeRLP() []byte {
	sibs := make([][]byte, len(p.Siblings))
	for i := range p.Siblings {
		sibs[i] = types.EncodeBytes(p.Siblings[i][:])
	}
	return types.EncodeList(
		types.EncodeUint(uint64(p.Algo)),
		types.EncodeUint(p.Index),
		types.EncodeUint(p.Total),
		types.EncodeList(sibs...),
	)
}

// DecodeMerkleProof parsea una prueba serializada con EncodeRLP.
func DecodeMerkleProof(b []byte) (*MerkleProof, error) {
	it, err := types.DecodeRLP(b)
	if err != nil {
		return nil, err
	}
	f, err := it.ListN(4)
	if err != nil {
		return nil, err
	}
	algo, err := f[0].Uint64()
	if err != nil {
		return nil, err
	}
	p := &MerkleProof{Algo: HashAlgo(algo)}
	if p.Index, err = f[1].Uint64(); err != nil {
		return nil, err
	}
	if p.Total, err = f[2].Uint64(); err != nil {
		return nil, err
	}
	sibs, err := f[3].Items()
	if err != nil {
		return nil, err
	}
	for _, s := range sibs {
		h, err := s.Hash()
		if err != nil {
			return nil, err
		}
		p.Siblings = append(p.Siblings, [32]byte(h))
	}
	if expectedSiblings(p.Index, p.Total) != len(p.Siblings) || p.Index >= p.Total {
		return nil, ErrMerkleProof
	}
	return p, nil
}
