package storage

// Almacén de bloques: esquema de claves y funciones de acceso "crudas"
// (estilo rawdb de go-ethereum), más BlockStore, que añade cachés LRU y la
// escritura atómica de un bloque completo con su índice canónico.
//
// Cabecera y cuerpo se guardan por separado para que la sincronización
// rápida pueda descargar primero sólo cabeceras y para que las consultas de
// cabeceras (muy frecuentes: consenso, RPC) no deserialicen transacciones.

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/l1/l1/types"
)

// Prefijos y claves del esquema (ver documentación del paquete).
var (
	headerPrefix       = []byte("h") // h + num + hash -> cabecera
	bodyPrefix         = []byte("b") // b + num + hash -> cuerpo
	headerNumberPrefix = []byte("H") // H + hash -> num
	canonicalPrefix    = []byte("n") // n + num -> hash
	txLookupPrefix     = []byte("l") // l + txHash -> entrada
	receiptsPrefix     = []byte("r") // r + num + hash -> recibos
	trieNodePrefix     = []byte("t") // t + hash -> nodo
	codePrefix         = []byte("c") // c + codeHash -> código
	preimagePrefix     = []byte("s") // s + hash -> preimagen
	checkpointPrefix   = []byte("k") // k + num -> checkpoint

	headBlockKey      = []byte("LastBlock")      // hash de la cabeza
	finalizedKey      = []byte("LastFinalized")  // hash del último finalizado
	lastCheckpointKey = []byte("LastCheckpoint") // número del último checkpoint
	schemaVersionKey  = []byte("SchemaVersion")  // versión del esquema
	genesisSpecKey    = []byte("Genesis")        // JSON del génesis
)

// ErrBlockNotFound indica que el bloque/cabecera solicitado no existe.
var ErrBlockNotFound = errors.New("storage: bloque no encontrado")

// encodeNumber codifica un número de bloque en 8 bytes big-endian.
func encodeNumber(n uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], n)
	return b[:]
}

// headerKey = h + num + hash.
func headerKey(n uint64, h types.Hash) []byte { return concat(headerPrefix, encodeNumber(n), h[:]) }

// bodyKey = b + num + hash.
func bodyKey(n uint64, h types.Hash) []byte { return concat(bodyPrefix, encodeNumber(n), h[:]) }

// headerNumberKey = H + hash.
func headerNumberKey(h types.Hash) []byte { return concat(headerNumberPrefix, h[:]) }

// canonicalKey = n + num.
func canonicalKey(n uint64) []byte { return concat(canonicalPrefix, encodeNumber(n)) }

// receiptsKey = r + num + hash.
func receiptsKey(n uint64, h types.Hash) []byte { return concat(receiptsPrefix, encodeNumber(n), h[:]) }

// trieNodeKey = t + hash.
func trieNodeKey(h types.Hash) []byte { return concat(trieNodePrefix, h[:]) }

// codeKey = c + hash.
func codeKey(h types.Hash) []byte { return concat(codePrefix, h[:]) }

// preimageKey = s + hash.
func preimageKey(h types.Hash) []byte { return concat(preimagePrefix, h[:]) }

// ---------------------------------------------------------------------
// Funciones crudas de cabeceras y cuerpos
// ---------------------------------------------------------------------

// WriteHeader guarda la cabecera y su entrada hash→número.
func WriteHeader(w KeyValueWriter, h *types.Header) error {
	hash := h.Hash()
	if err := w.Put(headerKey(h.Number, hash), h.EncodeRLP()); err != nil {
		return err
	}
	return w.Put(headerNumberKey(hash), encodeNumber(h.Number))
}

// ReadHeaderNumber devuelve el número del bloque con ese hash.
func ReadHeaderNumber(r KeyValueReader, hash types.Hash) (uint64, bool) {
	v, err := r.Get(headerNumberKey(hash))
	if err != nil || len(v) != 8 {
		return 0, false
	}
	return binary.BigEndian.Uint64(v), true
}

// ReadHeader lee la cabecera (num, hash).
func ReadHeader(r KeyValueReader, hash types.Hash, n uint64) (*types.Header, error) {
	v, err := r.Get(headerKey(n, hash))
	if errors.Is(err, ErrNotFound) {
		return nil, ErrBlockNotFound
	}
	if err != nil {
		return nil, err
	}
	return types.DecodeHeader(v)
}

// HasHeader informa si existe la cabecera.
func HasHeader(r KeyValueReader, hash types.Hash, n uint64) bool {
	ok, _ := r.Has(headerKey(n, hash))
	return ok
}

// DeleteHeader borra la cabecera y su índice de número.
func DeleteHeader(w KeyValueWriter, hash types.Hash, n uint64) error {
	if err := w.Delete(headerKey(n, hash)); err != nil {
		return err
	}
	return w.Delete(headerNumberKey(hash))
}

// WriteBody guarda el cuerpo del bloque.
func WriteBody(w KeyValueWriter, hash types.Hash, n uint64, b *types.Body) error {
	return w.Put(bodyKey(n, hash), b.EncodeRLP())
}

// ReadBody lee el cuerpo del bloque.
func ReadBody(r KeyValueReader, hash types.Hash, n uint64) (*types.Body, error) {
	v, err := r.Get(bodyKey(n, hash))
	if errors.Is(err, ErrNotFound) {
		return nil, ErrBlockNotFound
	}
	if err != nil {
		return nil, err
	}
	return types.DecodeBody(v)
}

// DeleteBody borra el cuerpo.
func DeleteBody(w KeyValueWriter, hash types.Hash, n uint64) error { return w.Delete(bodyKey(n, hash)) }

// WriteBlock guarda cabecera y cuerpo (no lo marca como canónico).
func WriteBlock(w KeyValueWriter, b *types.Block) error {
	if err := WriteHeader(w, b.HeaderRef()); err != nil {
		return err
	}
	return WriteBody(w, b.Hash(), b.Number(), b.Body())
}

// ReadBlock reconstruye un bloque completo.
func ReadBlock(r KeyValueReader, hash types.Hash, n uint64) (*types.Block, error) {
	h, err := ReadHeader(r, hash, n)
	if err != nil {
		return nil, err
	}
	body, err := ReadBody(r, hash, n)
	if err != nil {
		return nil, err
	}
	return types.NewBlock(h, body.Transactions, body.Justify), nil
}

// DeleteBlock borra cabecera, cuerpo y recibos del bloque.
func DeleteBlock(w KeyValueWriter, hash types.Hash, n uint64) error {
	if err := DeleteHeader(w, hash, n); err != nil {
		return err
	}
	if err := DeleteBody(w, hash, n); err != nil {
		return err
	}
	return DeleteReceipts(w, hash, n)
}

// ---------------------------------------------------------------------
// Índice canónico y punteros
// ---------------------------------------------------------------------

// WriteCanonicalHash fija el hash canónico de la altura n.
func WriteCanonicalHash(w KeyValueWriter, hash types.Hash, n uint64) error {
	return w.Put(canonicalKey(n), hash[:])
}

// ReadCanonicalHash devuelve el hash canónico de la altura n (cero si no hay).
func ReadCanonicalHash(r KeyValueReader, n uint64) types.Hash {
	v, err := r.Get(canonicalKey(n))
	if err != nil {
		return types.Hash{}
	}
	return types.BytesToHash(v)
}

// DeleteCanonicalHash elimina la entrada canónica de la altura n.
func DeleteCanonicalHash(w KeyValueWriter, n uint64) error { return w.Delete(canonicalKey(n)) }

// readHashKey lee un hash almacenado bajo una clave de metadatos.
func readHashKey(r KeyValueReader, key []byte) types.Hash {
	v, err := r.Get(key)
	if err != nil {
		return types.Hash{}
	}
	return types.BytesToHash(v)
}

// WriteHeadBlockHash fija la cabeza de la cadena.
func WriteHeadBlockHash(w KeyValueWriter, h types.Hash) error { return w.Put(headBlockKey, h[:]) }

// ReadHeadBlockHash devuelve la cabeza de la cadena (cero si no hay).
func ReadHeadBlockHash(r KeyValueReader) types.Hash { return readHashKey(r, headBlockKey) }

// WriteFinalizedHash fija el último bloque finalizado por el consenso BFT.
// Con HotStuff la finalidad es determinista: lo finalizado nunca se revierte.
func WriteFinalizedHash(w KeyValueWriter, h types.Hash) error { return w.Put(finalizedKey, h[:]) }

// ReadFinalizedHash devuelve el último bloque finalizado.
func ReadFinalizedHash(r KeyValueReader) types.Hash { return readHashKey(r, finalizedKey) }

// ---------------------------------------------------------------------
// BlockStore: fachada con caché
// ---------------------------------------------------------------------

// BlockStore ofrece acceso cacheado a bloques y cabeceras.
type BlockStore struct {
	db      KeyValueStore
	headers *LRU[types.Hash, *types.Header]
	bodies  *LRU[types.Hash, *types.Body]
}

// NewBlockStore crea el almacén con cachés de cache entradas (256 si ≤0).
func NewBlockStore(db KeyValueStore, cache int) *BlockStore {
	if cache <= 0 {
		cache = 256
	}
	return &BlockStore{db: db, headers: NewLRU[types.Hash, *types.Header](cache), bodies: NewLRU[types.Hash, *types.Body](cache)}
}

// DB devuelve el backend subyacente.
func (s *BlockStore) DB() KeyValueStore { return s.db }

// WriteBlock persiste atómicamente bloque, recibos (si no son nil) y, si
// canonical, el índice canónico, los índices de tx y el puntero de cabeza.
func (s *BlockStore) WriteBlock(b *types.Block, receipts types.Receipts, canonical bool) error {
	batch := s.db.NewBatch()
	if err := WriteBlock(batch, b); err != nil {
		return err
	}
	if receipts != nil {
		if err := WriteReceipts(batch, b.Hash(), b.Number(), receipts); err != nil {
			return err
		}
	}
	if canonical {
		if err := s.markCanonical(batch, b); err != nil {
			return err
		}
	}
	if err := batch.Write(); err != nil {
		return err
	}
	s.headers.Add(b.Hash(), b.HeaderRef())
	s.bodies.Add(b.Hash(), b.Body())
	return nil
}

// markCanonical escribe índice canónico, lookups de tx y cabeza.
func (s *BlockStore) markCanonical(w KeyValueWriter, b *types.Block) error {
	if err := WriteCanonicalHash(w, b.Hash(), b.Number()); err != nil {
		return err
	}
	if err := WriteTxLookupEntries(w, b); err != nil {
		return err
	}
	return WriteHeadBlockHash(w, b.Hash())
}

// SetCanonical marca como canónico un bloque ya almacenado (p. ej. al
// cambiar de rama antes de la finalidad).
func (s *BlockStore) SetCanonical(hash types.Hash) error {
	b, err := s.BlockByHash(hash)
	if err != nil {
		return err
	}
	batch := s.db.NewBatch()
	if err := s.markCanonical(batch, b); err != nil {
		return err
	}
	return batch.Write()
}

// Rewind deshace la canonicidad de las alturas > n (borrando sus índices
// de tx) y fija la cabeza en el bloque canónico n. No borra los bloques.
func (s *BlockStore) Rewind(n uint64) error {
	target := ReadCanonicalHash(s.db, n)
	if target.IsZero() {
		return fmt.Errorf("%w: altura canónica %d", ErrBlockNotFound, n)
	}
	head := s.CurrentHeader()
	batch := s.db.NewBatch()
	if head != nil {
		for i := head.Number; i > n; i-- {
			if b, err := s.BlockByNumber(i); err == nil {
				for _, tx := range b.Transactions() {
					if err := DeleteTxLookupEntry(batch, tx.Hash()); err != nil {
						return err
					}
				}
			}
			if err := DeleteCanonicalHash(batch, i); err != nil {
				return err
			}
		}
	}
	if err := WriteHeadBlockHash(batch, target); err != nil {
		return err
	}
	return batch.Write()
}

// HeaderByHash devuelve una cabecera por hash (cacheada).
func (s *BlockStore) HeaderByHash(hash types.Hash) (*types.Header, error) {
	if h, ok := s.headers.Get(hash); ok {
		return h, nil
	}
	n, ok := ReadHeaderNumber(s.db, hash)
	if !ok {
		return nil, ErrBlockNotFound
	}
	h, err := ReadHeader(s.db, hash, n)
	if err != nil {
		return nil, err
	}
	s.headers.Add(hash, h)
	return h, nil
}

// HeaderByNumber devuelve la cabecera canónica de la altura n.
func (s *BlockStore) HeaderByNumber(n uint64) (*types.Header, error) {
	hash := ReadCanonicalHash(s.db, n)
	if hash.IsZero() {
		return nil, ErrBlockNotFound
	}
	return s.HeaderByHash(hash)
}

// BlockByHash devuelve un bloque completo por hash.
func (s *BlockStore) BlockByHash(hash types.Hash) (*types.Block, error) {
	h, err := s.HeaderByHash(hash)
	if err != nil {
		return nil, err
	}
	body, ok := s.bodies.Get(hash)
	if !ok {
		if body, err = ReadBody(s.db, hash, h.Number); err != nil {
			return nil, err
		}
		s.bodies.Add(hash, body)
	}
	return types.NewBlock(h, body.Transactions, body.Justify), nil
}

// BlockByNumber devuelve el bloque canónico de la altura n.
func (s *BlockStore) BlockByNumber(n uint64) (*types.Block, error) {
	hash := ReadCanonicalHash(s.db, n)
	if hash.IsZero() {
		return nil, ErrBlockNotFound
	}
	return s.BlockByHash(hash)
}

// HasBlock informa si el bloque (cabecera y cuerpo) está almacenado.
func (s *BlockStore) HasBlock(hash types.Hash, n uint64) bool {
	ok, _ := s.db.Has(bodyKey(n, hash))
	return ok && HasHeader(s.db, hash, n)
}

// CurrentHeader devuelve la cabecera de la cabeza (nil si la base está vacía).
func (s *BlockStore) CurrentHeader() *types.Header {
	h, err := s.HeaderByHash(ReadHeadBlockHash(s.db))
	if err != nil {
		return nil
	}
	return h
}

// CurrentBlock devuelve el bloque cabeza (nil si no hay).
func (s *BlockStore) CurrentBlock() *types.Block {
	b, err := s.BlockByHash(ReadHeadBlockHash(s.db))
	if err != nil {
		return nil
	}
	return b
}

// SetFinalized registra el último bloque finalizado.
func (s *BlockStore) SetFinalized(hash types.Hash) error { return WriteFinalizedHash(s.db, hash) }

// FinalizedHeader devuelve la cabecera finalizada (nil si no hay).
func (s *BlockStore) FinalizedHeader() *types.Header {
	h, err := s.HeaderByHash(ReadFinalizedHash(s.db))
	if err != nil {
		return nil
	}
	return h
}

// Receipts devuelve los recibos (con campos derivados) de un bloque.
func (s *BlockStore) Receipts(hash types.Hash) (types.Receipts, error) {
	b, err := s.BlockByHash(hash)
	if err != nil {
		return nil, err
	}
	return ReadReceipts(s.db, hash, b.Number(), b.Transactions())
}

// Transaction busca una transacción canónica por hash.
func (s *BlockStore) Transaction(txHash types.Hash) (*types.Transaction, *TxLookupEntry, error) {
	return ReadTransaction(s.db, txHash)
}

// PurgeCache vacía las cachés (tras un Rewind o una importación externa).
func (s *BlockStore) PurgeCache() { s.headers.Purge(); s.bodies.Purge() }
