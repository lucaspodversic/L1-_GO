package crypto

// Firmantes. Un Signer abstrae "quién firma" (clave local en memoria hoy;
// en el futuro un HSM o un firmante remoto) y aplica separación de dominio:
// cada tipo de mensaje del protocolo (voto, propuesta, timeout, handshake
// P2P...) se firma bajo un dominio distinto, de modo que una firma válida en
// un contexto nunca sea reutilizable en otro.
//
// También se implementa aquí la firma de transacciones y la recuperación del
// remitente (TxSigner), con caché en la propia transacción.

import (
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/l1/l1/types"
)

// Dominios de firma del protocolo. El sufijo de versión permite cambiar el
// formato de un mensaje sin ambigüedad con firmas antiguas.
const (
	DomainProposal  = "l1/consensus/proposal/v1"
	DomainVote      = "l1/consensus/vote/v1"
	DomainTimeout   = "l1/consensus/timeout/v1"
	DomainNewView   = "l1/consensus/newview/v1"
	DomainHandshake = "l1/p2p/handshake/v1"
	DomainPeerRec   = "l1/p2p/record/v1"
	DomainVRF       = "l1/consensus/vrf/v1"
)

// DomainMessage construye el mensaje con separación de dominio:
// len(domain) (uint16 BE) || domain || chainID (uint64 BE) || msg.
// Prefijar la longitud impide colisiones entre (dominio, mensaje) distintos
// cuya concatenación coincida; incluir el chain ID evita replays entre redes.
func DomainMessage(domain string, chainID types.ChainID, msg []byte) []byte {
	out := make([]byte, 0, 2+len(domain)+8+len(msg))
	out = binary.BigEndian.AppendUint16(out, uint16(len(domain)))
	out = append(out, domain...)
	out = binary.BigEndian.AppendUint64(out, uint64(chainID))
	return append(out, msg...)
}

// Signer es cualquier entidad capaz de producir firmas.
type Signer interface {
	// Scheme devuelve el esquema de firma.
	Scheme() KeyType
	// PublicKey devuelve la clave pública con la que verificar.
	PublicKey() PublicKey
	// Sign firma un mensaje crudo (sin dominio).
	Sign(msg []byte) ([]byte, error)
	// SignDomain firma msg bajo un dominio y chain ID.
	SignDomain(domain string, chainID types.ChainID, msg []byte) ([]byte, error)
}

// LocalSigner es un Signer respaldado por una clave privada en memoria.
// Es seguro para uso concurrente (las claves son inmutables).
type LocalSigner struct {
	priv PrivateKey
	pub  PublicKey
}

// NewLocalSigner crea un firmante local.
func NewLocalSigner(priv PrivateKey) *LocalSigner {
	return &LocalSigner{priv: priv, pub: priv.Public()}
}

// Scheme implementa Signer.
func (s *LocalSigner) Scheme() KeyType { return s.priv.Scheme() }

// PublicKey implementa Signer.
func (s *LocalSigner) PublicKey() PublicKey { return s.pub }

// PrivateKey expone la clave subyacente (p. ej. para VRF con BLS).
func (s *LocalSigner) PrivateKey() PrivateKey { return s.priv }

// Sign implementa Signer.
func (s *LocalSigner) Sign(msg []byte) ([]byte, error) { return s.priv.Sign(msg) }

// SignDomain implementa Signer.
func (s *LocalSigner) SignDomain(domain string, chainID types.ChainID, msg []byte) ([]byte, error) {
	return s.priv.Sign(DomainMessage(domain, chainID, msg))
}

// ---------------------------------------------------------------------------
// Transacciones.
// ---------------------------------------------------------------------------

// TxSigner firma transacciones y recupera remitentes para un chain ID dado.
type TxSigner struct {
	chainID types.ChainID
}

// NewTxSigner crea un TxSigner ligado a chainID.
func NewTxSigner(chainID types.ChainID) TxSigner { return TxSigner{chainID: chainID} }

// ChainID devuelve el chain ID del firmante.
func (s TxSigner) ChainID() types.ChainID { return s.chainID }

// SignTx firma tx con key y devuelve una copia firmada (tx no se modifica).
// Si tx.ChainID es cero se rellena con el del firmante; si difiere, error.
func (s TxSigner) SignTx(tx *types.Transaction, key *Secp256k1PrivateKey) (*types.Transaction, error) {
	c := tx.Copy()
	if c.ChainID == 0 {
		c.ChainID = s.chainID
	}
	if c.ChainID != s.chainID {
		return nil, fmt.Errorf("%w: tx %d, firmante %d", types.ErrInvalidChainID, c.ChainID, s.chainID)
	}
	h, err := c.SigningHash()
	if err != nil {
		return nil, err
	}
	sig, err := key.SignHash(h)
	if err != nil {
		return nil, err
	}
	signed := c.WithSignature(sig)
	// Ya conocemos el remitente: lo cacheamos para ahorrar una recuperación.
	signed.SetCachedSender(key.Address())
	return signed, nil
}

// Sender recupera el remitente de tx (usando la caché si existe). Valida
// que el chain ID coincida y que la firma tenga S bajo.
func (s TxSigner) Sender(tx *types.Transaction) (types.Address, error) {
	if a, ok := tx.CachedSender(); ok {
		return a, nil
	}
	if tx.ChainID != s.chainID {
		return types.Address{}, fmt.Errorf("%w: tx %d, esperado %d", types.ErrInvalidChainID, tx.ChainID, s.chainID)
	}
	if !tx.IsSigned() {
		return types.Address{}, types.ErrUnsignedTx
	}
	if !tx.Sig.ValidateValues(true) {
		return types.Address{}, types.ErrInvalidSignature
	}
	h, err := tx.SigningHash()
	if err != nil {
		return types.Address{}, err
	}
	addr, err := RecoverAddress(h, tx.Sig)
	if err != nil {
		return types.Address{}, err
	}
	tx.SetCachedSender(addr)
	return addr, nil
}

// SignTx es un atajo de NewTxSigner(tx.ChainID).SignTx.
func SignTx(tx *types.Transaction, key *Secp256k1PrivateKey) (*types.Transaction, error) {
	return NewTxSigner(tx.ChainID).SignTx(tx, key)
}

// RecoverSenders recupera en paralelo los remitentes de un lote de
// transacciones (útil al importar bloques: la recuperación ECDSA domina el
// coste de validación). Devuelve el primer error encontrado, con su índice.
func (s TxSigner) RecoverSenders(txs []*types.Transaction, workers int) ([]types.Address, error) {
	if workers <= 0 {
		workers = 4
	}
	out := make([]types.Address, len(txs))
	errs := make([]error, len(txs))
	var wg sync.WaitGroup
	next := make(chan int)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				out[i], errs[i] = s.Sender(txs[i])
			}
		}()
	}
	for i := range txs {
		next <- i
	}
	close(next)
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			return nil, fmt.Errorf("tx %d (%s): %w", i, txs[i].Hash(), err)
		}
	}
	return out, nil
}
