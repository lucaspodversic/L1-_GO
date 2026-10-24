package crypto

// Árbol de Merkle binario, estilo RFC 6962 (Certificate Transparency):
//
//   - hoja:  H(0x00 || dato)
//   - nodo:  H(0x01 || izquierdo || derecho)
//
// Los prefijos distintos para hojas y nodos internos impiden los ataques de
// "segunda preimagen" en los que un nodo interno se hace pasar por hoja.
// Cuando un nivel tiene un número impar de nodos, el último se PROMUEVE sin
// cambios al nivel superior (no se duplica, como hace Bitcoin, lo que causó
// CVE-2012-2459). Esto produce exactamente el mismo árbol que la división
// recursiva por la mayor potencia de dos de RFC 6962.
//
// Este árbol se usa donde no se necesita la estructura de clave/valor del
// trie de Patricia: raíces de lotes de fragmentos de snapshot para sync,
// compromisos de conjuntos de validadores y pruebas ligeras.

// Prefijos de separación de dominio hoja/nodo.
const (
	merkleLeafPrefix = 0x00
	merkleNodePrefix = 0x01
)

// MerkleTree es un árbol de Merkle inmutable construido de una vez.
// levels[0] son los hashes de las hojas y levels[len-1] contiene la raíz.
type MerkleTree struct {
	hasher Hasher
	levels [][][32]byte
}

// MerkleLeafHash calcula el hash de hoja H(0x00 || data).
func MerkleLeafHash(h Hasher, data []byte) [32]byte {
	return h.Sum([]byte{merkleLeafPrefix}, data)
}

// MerkleNodeHash calcula el hash de nodo H(0x01 || l || r).
func MerkleNodeHash(h Hasher, l, r [32]byte) [32]byte {
	return h.Sum([]byte{merkleNodePrefix}, l[:], r[:])
}

// MerkleEmptyRoot es la raíz de un árbol sin hojas: H("") (RFC 6962).
func MerkleEmptyRoot(h Hasher) [32]byte { return h.Sum() }

// NewMerkleTree construye el árbol a partir de los datos de las hojas.
// Si h es nil se usa Keccak-256.
func NewMerkleTree(h Hasher, leaves [][]byte) *MerkleTree {
	if h == nil {
		h = KeccakHasher{}
	}
	hashes := make([][32]byte, len(leaves))
	for i, l := range leaves {
		hashes[i] = MerkleLeafHash(h, l)
	}
	return NewMerkleTreeFromHashes(h, hashes)
}

// NewMerkleTreeFromHashes construye el árbol a partir de hashes de hoja ya
// calculados (H(0x00||dato)). El slice se copia.
func NewMerkleTreeFromHashes(h Hasher, leafHashes [][32]byte) *MerkleTree {
	if h == nil {
		h = KeccakHasher{}
	}
	t := &MerkleTree{hasher: h}
	level := append([][32]byte(nil), leafHashes...)
	t.levels = append(t.levels, level)
	for len(level) > 1 {
		next := make([][32]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				next = append(next, level[i]) // impar: se promueve
				continue
			}
			next = append(next, MerkleNodeHash(h, level[i], level[i+1]))
		}
		t.levels = append(t.levels, next)
		level = next
	}
	return t
}

// Hasher devuelve la función de hash del árbol.
func (t *MerkleTree) Hasher() Hasher { return t.hasher }

// Len devuelve el número de hojas.
func (t *MerkleTree) Len() int { return len(t.levels[0]) }

// Root devuelve la raíz (MerkleEmptyRoot si no hay hojas).
func (t *MerkleTree) Root() [32]byte {
	if t.Len() == 0 {
		return MerkleEmptyRoot(t.hasher)
	}
	return t.levels[len(t.levels)-1][0]
}

// Leaf devuelve el hash de la hoja i.
func (t *MerkleTree) Leaf(i int) [32]byte { return t.levels[0][i] }

// Prove genera la prueba de inclusión de la hoja index.
func (t *MerkleTree) Prove(index int) (*MerkleProof, error) {
	n := t.Len()
	if index < 0 || index >= n {
		return nil, ErrMerkleIndex
	}
	p := &MerkleProof{Algo: t.hasher.Algo(), Index: uint64(index), Total: uint64(n)}
	idx := index
	for lvl := 0; lvl < len(t.levels)-1; lvl++ {
		nodes := t.levels[lvl]
		sib := idx ^ 1
		if sib < len(nodes) {
			p.Siblings = append(p.Siblings, nodes[sib])
		}
		// Si sib ≥ len, el nodo fue promovido y no aporta hermano.
		idx /= 2
	}
	return p, nil
}

// MerkleRoot es un atajo para calcular sólo la raíz de unos datos.
func MerkleRoot(h Hasher, leaves [][]byte) [32]byte { return NewMerkleTree(h, leaves).Root() }
