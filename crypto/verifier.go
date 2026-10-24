package crypto

// Verificación de firmas genérica por esquema y verificación por lotes.
// La capa de consenso recibe firmas como (esquema, clave pública, mensaje,
// firma) y no debería tener que saber cómo se verifica cada esquema; este
// archivo concentra esa lógica.

import (
	"fmt"
	"runtime"
	"sync"

	"github.com/l1/l1/types"
)

// Verify verifica sig sobre msg con la clave pública serializada pub del
// esquema indicado. Devuelve error sólo si la clave no puede parsearse; una
// firma inválida produce (false, nil).
func Verify(scheme KeyType, pub, msg, sig []byte) (bool, error) {
	pk, err := PublicKeyFromBytes(scheme, pub)
	if err != nil {
		return false, err
	}
	return pk.Verify(msg, sig), nil
}

// VerifyDomain verifica una firma producida con Signer.SignDomain.
func VerifyDomain(pk PublicKey, domain string, chainID types.ChainID, msg, sig []byte) bool {
	return pk.Verify(DomainMessage(domain, chainID, msg), sig)
}

// VerifySchemeSignature verifica un types.SchemeSignature contra pk.
func VerifySchemeSignature(pk PublicKey, msg []byte, s types.SchemeSignature) bool {
	if s.Validate() != nil || s.Scheme != pk.Scheme() {
		return false
	}
	return pk.Verify(msg, s.Bytes)
}

// VerifyTx valida estáticamente tx (ValidateBasic) y recupera su remitente.
func VerifyTx(tx *types.Transaction, chainID types.ChainID) (types.Address, error) {
	if err := tx.ValidateBasic(chainID); err != nil {
		return types.Address{}, err
	}
	return NewTxSigner(chainID).Sender(tx)
}

// batchEntry es un elemento pendiente de BatchVerifier.
type batchEntry struct {
	pk  PublicKey
	msg []byte
	sig []byte
}

// BatchVerifier acumula firmas y las verifica todas juntas. Las firmas BLS
// se verifican con una única comprobación de pairing aleatorizada; las demás
// en paralelo. Si el lote falla se identifica qué entradas son inválidas.
// No es seguro para uso concurrente.
type BatchVerifier struct {
	entries []batchEntry
}

// NewBatchVerifier crea un verificador vacío con capacidad inicial n.
func NewBatchVerifier(n int) *BatchVerifier {
	return &BatchVerifier{entries: make([]batchEntry, 0, n)}
}

// Add encola una verificación.
func (b *BatchVerifier) Add(pk PublicKey, msg, sig []byte) {
	b.entries = append(b.entries, batchEntry{pk: pk, msg: msg, sig: sig})
}

// Len devuelve el número de entradas encoladas.
func (b *BatchVerifier) Len() int { return len(b.entries) }

// Verify verifica todas las entradas. Devuelve true si todas son válidas; en
// caso contrario, false y los índices (en orden de Add) de las inválidas.
func (b *BatchVerifier) Verify() (bool, []int) {
	valid := make([]bool, len(b.entries))

	// 1) Separar BLS del resto.
	var blsIdx []int
	var blsPks []*BLSPublicKey
	var blsMsgs [][]byte
	var blsSigs []*BLSSignature
	var other []int
	for i, e := range b.entries {
		if pk, ok := e.pk.(*BLSPublicKey); ok {
			s, err := BLSSignatureFromBytes(e.sig)
			if err != nil {
				continue // firma malformada: inválida
			}
			blsIdx = append(blsIdx, i)
			blsPks = append(blsPks, pk)
			blsMsgs = append(blsMsgs, e.msg)
			blsSigs = append(blsSigs, s)
			continue
		}
		other = append(other, i)
	}

	// 2) BLS: intento de lote; si falla, verificación individual para
	//    localizar las firmas incorrectas.
	if len(blsIdx) > 0 {
		if blsBatchVerify(blsPks, blsMsgs, blsSigs) {
			for _, i := range blsIdx {
				valid[i] = true
			}
		} else {
			for j, i := range blsIdx {
				valid[i] = blsPks[j].VerifyBLS(blsMsgs[j], blsSigs[j])
			}
		}
	}

	// 3) Resto: paralelo con tantos workers como CPUs.
	var wg sync.WaitGroup
	sem := make(chan struct{}, runtime.GOMAXPROCS(0))
	for _, i := range other {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			e := b.entries[i]
			valid[i] = e.pk != nil && e.pk.Verify(e.msg, e.sig)
		}(i)
	}
	wg.Wait()

	var bad []int
	for i, ok := range valid {
		if !ok {
			bad = append(bad, i)
		}
	}
	return len(bad) == 0, bad
}

// Reset vacía el verificador para reutilizarlo.
func (b *BatchVerifier) Reset() { b.entries = b.entries[:0] }

// MustVerify es como Verify pero devuelve un error descriptivo.
func (b *BatchVerifier) MustVerify() error {
	if ok, bad := b.Verify(); !ok {
		return fmt.Errorf("%w: %d firmas inválidas (índices %v)", types.ErrInvalidSignature, len(bad), bad)
	}
	return nil
}
