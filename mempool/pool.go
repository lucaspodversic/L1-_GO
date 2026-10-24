package mempool

// Este archivo es el núcleo del pool de transacciones (TxPool).
//
// Estructura:
//   - all: índice hash → tx de todo el pool (separando locales y remotas).
//   - pending[addr]: txs ejecutables (nonces contiguos desde el de estado).
//   - queue[addr]: txs futuras (con hueco de nonce).
//   - priced: montículo de remotas por precio para el desalojo.
//   - nonces: nonce pendiente por cuenta.
//
// Flujo de una tx entrante: validación sin estado → validación con estado
// → (pool lleno: desalojo por precio o rechazo) → si reemplaza una
// pendiente, sustitución in situ; si no, entra en queue y se intenta
// promover a pending. Con cada bloque nuevo, Reset retira lo incluido,
// degrada lo que dejó de ser ejecutable y promueve lo que pasó a serlo.

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/l1/l1/crypto"
	"github.com/l1/l1/execution"
	"github.com/l1/l1/types"
)

// Config son los parámetros del pool.
type Config struct {
	ChainID      types.ChainID
	PriceBump    uint64       // % mínimo para reemplazar
	MinTip       types.Amount // propina mínima para remotas
	AccountSlots int          // txs ejecutables garantizadas por cuenta
	AccountQueue int          // txs futuras máximas por cuenta
	GlobalSlots  int          // capacidad de pending
	GlobalQueue  int          // capacidad de queue
	MaxNonceGap  uint64       // adelanto máximo del nonce
	Lifetime     time.Duration
	MaxTxSize    uint64
	Fees         execution.FeeConfig
	Filters      TxFilter
	NoLocals     bool // tratar todas como remotas
}

// DefaultConfig devuelve una configuración razonable.
func DefaultConfig(chainID types.ChainID) Config {
	return Config{
		ChainID: chainID, PriceBump: DefaultPriceBump, MinTip: types.NewAmount(1),
		AccountSlots: 16, AccountQueue: 64, GlobalSlots: 4096, GlobalQueue: 1024,
		MaxNonceGap: 64, Lifetime: 3 * time.Hour, MaxTxSize: types.MaxTxSize,
		Fees: execution.DefaultFeeConfig(),
	}
}

// sanitize corrige valores no válidos.
func (c *Config) sanitize() {
	d := DefaultConfig(c.ChainID)
	if c.PriceBump == 0 {
		c.PriceBump = d.PriceBump
	}
	if c.AccountSlots <= 0 {
		c.AccountSlots = d.AccountSlots
	}
	if c.AccountQueue <= 0 {
		c.AccountQueue = d.AccountQueue
	}
	if c.GlobalSlots <= 0 {
		c.GlobalSlots = d.GlobalSlots
	}
	if c.GlobalQueue <= 0 {
		c.GlobalQueue = d.GlobalQueue
	}
	if c.MaxTxSize == 0 {
		c.MaxTxSize = d.MaxTxSize
	}
	if c.Fees.BaseFeeChangeDenominator == 0 {
		c.Fees = d.Fees
	}
}

// txLookup es el índice hash → tx.
type txLookup struct {
	mu      sync.RWMutex
	locals  map[types.Hash]*types.Transaction
	remotes map[types.Hash]*types.Transaction
	seen    map[types.Hash]time.Time
}

func newTxLookup() *txLookup {
	return &txLookup{locals: map[types.Hash]*types.Transaction{}, remotes: map[types.Hash]*types.Transaction{}, seen: map[types.Hash]time.Time{}}
}

// Get busca en ambos conjuntos.
func (t *txLookup) Get(h types.Hash) *types.Transaction {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if tx := t.locals[h]; tx != nil {
		return tx
	}
	return t.remotes[h]
}

// GetRemote busca sólo en remotas.
func (t *txLookup) GetRemote(h types.Hash) *types.Transaction {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.remotes[h]
}

// Seen devuelve cuándo llegó la tx.
func (t *txLookup) Seen(h types.Hash) time.Time {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.seen[h]
}

// Add indexa una tx.
func (t *txLookup) Add(tx *types.Transaction, local bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if local {
		t.locals[tx.Hash()] = tx
	} else {
		t.remotes[tx.Hash()] = tx
	}
	t.seen[tx.Hash()] = time.Now()
}

// Remove desindexa una tx.
func (t *txLookup) Remove(h types.Hash) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.locals, h)
	delete(t.remotes, h)
	delete(t.seen, h)
}

// Count devuelve el total.
func (t *txLookup) Count() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.locals) + len(t.remotes)
}

// RangeRemote recorre las remotas.
func (t *txLookup) RangeRemote(f func(*types.Transaction) bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	for _, tx := range t.remotes {
		if !f(tx) {
			return
		}
	}
}

// TxPool es el pool de transacciones. Es seguro para uso concurrente.
type TxPool struct {
	mu      sync.RWMutex
	config  Config
	signer  crypto.TxSigner
	state   StateReader
	head    *types.Header
	baseFee types.Amount // base fee del SIGUIENTE bloque
	gasCap  uint64       // límite de gas del siguiente bloque

	all     *txLookup
	priced  *pricedList
	pending map[types.Address]*txList
	queue   map[types.Address]*txList
	beats   map[types.Address]time.Time // última actividad de cada cuenta
	locals  map[types.Address]bool
	nonces  *nonceTracker
	metrics *Metrics
}

// New crea el pool sobre la cabecera actual y su estado.
func New(config Config, head *types.Header, state StateReader) *TxPool {
	config.sanitize()
	pool := &TxPool{
		config:  config,
		signer:  crypto.NewTxSigner(config.ChainID),
		all:     newTxLookup(),
		pending: map[types.Address]*txList{},
		queue:   map[types.Address]*txList{},
		beats:   map[types.Address]time.Time{},
		locals:  map[types.Address]bool{},
		nonces:  newNonceTracker(state),
		metrics: newMetrics(),
	}
	pool.priced = newPricedList(pool.all)
	pool.setHead(head, state)
	return pool
}

// setHead actualiza cabecera, estado y parámetros del siguiente bloque.
func (pool *TxPool) setHead(head *types.Header, state StateReader) {
	pool.head, pool.state = head, state
	pool.baseFee = execution.CalcBaseFee(pool.config.Fees, head)
	pool.gasCap = head.GasLimit
	pool.nonces.reset(state)
	pool.priced.SetBaseFee(pool.baseFee)
}

// Metrics devuelve los contadores.
func (pool *TxPool) Metrics() *Metrics { return pool.metrics }

// Signer devuelve el firmante de la cadena.
func (pool *TxPool) Signer() crypto.TxSigner { return pool.signer }

// BaseFee devuelve la base fee prevista para el siguiente bloque.
func (pool *TxPool) BaseFee() types.Amount {
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	return pool.baseFee
}

// AddLocal añade transacciones locales (RPC del propio nodo).
func (pool *TxPool) AddLocal(tx *types.Transaction) error {
	return pool.Add([]*types.Transaction{tx}, !pool.config.NoLocals)[0]
}

// AddRemote añade una transacción recibida por la red.
func (pool *TxPool) AddRemote(tx *types.Transaction) error {
	return pool.Add([]*types.Transaction{tx}, false)[0]
}

// Add añade un lote y devuelve un error por transacción.
func (pool *TxPool) Add(txs []*types.Transaction, local bool) []error {
	errs := make([]error, len(txs))
	senders := make([]types.Address, len(txs))
	// Fase sin estado, fuera del cerrojo principal.
	pool.mu.RLock()
	opts := &ValidationOptions{ChainID: pool.config.ChainID, MaxSize: pool.config.MaxTxSize, MaxGas: pool.gasCap,
		MinTip: pool.config.MinTip, Filters: pool.config.Filters, Signer: pool.signer, Local: local}
	pool.mu.RUnlock()
	for i, tx := range txs {
		if pool.all.Get(tx.Hash()) != nil {
			errs[i] = ErrAlreadyKnown
			continue
		}
		senders[i], errs[i] = ValidateTxBasics(tx, opts)
	}
	pool.mu.Lock()
	dirty := map[types.Address]struct{}{}
	for i, tx := range txs {
		if errs[i] != nil {
			continue
		}
		replaced, err := pool.add(tx, senders[i], local)
		errs[i] = err
		if err == nil && !replaced {
			dirty[senders[i]] = struct{}{}
		}
	}
	pool.promoteExecutables(dirty)
	pool.mu.Unlock()
	for _, err := range errs {
		if err != nil {
			pool.metrics.reject(err)
		} else {
			pool.metrics.Added.Add(1)
		}
	}
	return errs
}

// add inserta una tx validada. Devuelve si reemplazó una pendiente.
func (pool *TxPool) add(tx *types.Transaction, from types.Address, local bool) (bool, error) {
	hash := tx.Hash()
	if pool.all.Get(hash) != nil {
		return false, ErrAlreadyKnown
	}
	if local {
		pool.locals[from] = true
	}
	local = local || pool.locals[from]
	// Coste de las anteriores del remitente (deben poder pagarse todas).
	var existing types.Amount
	pendingNonce := pool.nonces.get(from)
	if l := pool.pending[from]; l != nil {
		existing = existing.Add(l.CostBelow(tx.Nonce))
	}
	if l := pool.queue[from]; l != nil {
		existing = existing.Add(l.CostBelow(tx.Nonce))
	}
	if err := ValidateTxState(tx, from, &StateOptions{State: pool.state, ExistingCost: existing,
		MaxNonceGap: pool.config.MaxNonceGap, PendingNonce: pendingNonce}); err != nil {
		return false, err
	}
	isReplacement := (pool.pending[from] != nil && pool.pending[from].Overlaps(tx)) ||
		(pool.queue[from] != nil && pool.queue[from].Overlaps(tx))
	// Límite por cuenta (los reemplazos no suman).
	if !isReplacement && !local {
		n := 0
		if l := pool.pending[from]; l != nil {
			n += l.Len()
		}
		if l := pool.queue[from]; l != nil {
			n += l.Len()
		}
		if n >= pool.config.AccountSlots+pool.config.AccountQueue {
			return false, ErrAccountLimit
		}
	}
	// Pool lleno: hay que desalojar una más barata o rechazar.
	if !isReplacement && pool.all.Count() >= pool.config.GlobalSlots+pool.config.GlobalQueue {
		if !local && pool.priced.Underpriced(tx) {
			return false, ErrUnderpriced
		}
		drop := pool.priced.Discard(pool.all.Count() - (pool.config.GlobalSlots + pool.config.GlobalQueue) + 1)
		if len(drop) == 0 {
			return false, ErrTxPoolOverflow
		}
		for _, d := range drop {
			pool.removeTx(d.Hash(), false)
			pool.metrics.Discarded.Add(1)
		}
	}
	// Reemplazo de una pendiente: in situ.
	if l := pool.pending[from]; l != nil && l.Overlaps(tx) {
		inserted, old := l.Add(tx, pool.config.PriceBump)
		if !inserted {
			return false, ErrReplaceUnderpriced
		}
		pool.all.Remove(old.Hash())
		pool.priced.Removed(1)
		pool.metrics.Replaced.Add(1)
		pool.all.Add(tx, local)
		pool.priced.Put(tx, local)
		pool.beats[from] = time.Now()
		return true, nil
	}
	// Si no, a la cola de futuras (con posible reemplazo).
	if _, err := pool.enqueue(tx, from, local); err != nil {
		return false, err
	}
	return false, nil
}

// enqueue inserta en queue (o reemplaza en queue).
func (pool *TxPool) enqueue(tx *types.Transaction, from types.Address, local bool) (bool, error) {
	q := pool.queue[from]
	if q == nil {
		q = newTxList(false)
		pool.queue[from] = q
	}
	inserted, old := q.Add(tx, pool.config.PriceBump)
	if !inserted {
		return false, ErrReplaceUnderpriced
	}
	if old != nil {
		pool.all.Remove(old.Hash())
		pool.priced.Removed(1)
		pool.metrics.Replaced.Add(1)
	}
	if pool.all.Get(tx.Hash()) == nil {
		pool.all.Add(tx, local)
		pool.priced.Put(tx, local)
	}
	if _, ok := pool.beats[from]; !ok {
		pool.beats[from] = time.Now()
	}
	return old != nil, nil
}

// promoteExecutables mueve de queue a pending lo que pasó a ser
// ejecutable en las cuentas dadas (nil = todas).
func (pool *TxPool) promoteExecutables(accounts map[types.Address]struct{}) {
	if accounts == nil {
		accounts = make(map[types.Address]struct{}, len(pool.queue))
		for a := range pool.queue {
			accounts[a] = struct{}{}
		}
	}
	for addr := range accounts {
		q := pool.queue[addr]
		if q == nil {
			continue
		}
		// Ya incluidas en bloques.
		for _, tx := range q.Forward(pool.state.GetNonce(addr)) {
			pool.all.Remove(tx.Hash())
			pool.priced.Removed(1)
		}
		// Ya no pagables.
		drops, _ := q.Filter(pool.state.GetBalance(addr), pool.gasCap)
		for _, tx := range drops {
			pool.all.Remove(tx.Hash())
			pool.priced.Removed(1)
		}
		// Contiguas a partir del nonce pendiente.
		ready := q.Ready(pool.nonces.get(addr))
		if len(ready) > 0 {
			p := pool.pending[addr]
			if p == nil {
				p = newTxList(true)
				pool.pending[addr] = p
			}
			for _, tx := range ready {
				p.put(tx)
			}
			pool.nonces.set(addr, ready[len(ready)-1].Nonce+1)
			pool.beats[addr] = time.Now()
			pool.metrics.Promoted.Add(uint64(len(ready)))
		}
		// Tope de futuras por cuenta (salvo locales).
		if !pool.locals[addr] {
			for _, tx := range q.Cap(pool.config.AccountQueue) {
				pool.all.Remove(tx.Hash())
				pool.priced.Removed(1)
			}
		}
		if q.Empty() {
			delete(pool.queue, addr)
		}
	}
}

// demoteUnexecutables revisa pending tras un cambio de estado: quita lo
// incluido, lo impagable y degrada a queue lo que perdió contigüidad.
func (pool *TxPool) demoteUnexecutables() {
	for addr, list := range pool.pending {
		nonce := pool.state.GetNonce(addr)
		olds := list.Forward(nonce)
		for _, tx := range olds {
			pool.all.Remove(tx.Hash())
		}
		pool.priced.Removed(len(olds))
		pool.metrics.Included.Add(uint64(len(olds)))
		drops, invalids := list.Filter(pool.state.GetBalance(addr), pool.gasCap)
		for _, tx := range drops {
			pool.all.Remove(tx.Hash())
		}
		pool.priced.Removed(len(drops))
		for _, tx := range invalids {
			pool.enqueue(tx, addr, pool.locals[addr]) //nolint:errcheck // reinsertar en queue nunca falla
			pool.metrics.Demoted.Add(1)
		}
		// Hueco al principio: todo pasa a queue.
		if list.Len() > 0 && list.Get(nonce) == nil {
			for _, tx := range list.Cap(0) {
				pool.enqueue(tx, addr, pool.locals[addr]) //nolint:errcheck
				pool.metrics.Demoted.Add(1)
			}
		}
		if list.Empty() {
			delete(pool.pending, addr)
		}
	}
	// Recalculamos los nonces pendientes.
	all := make(map[types.Address]uint64, len(pool.pending))
	for addr, list := range pool.pending {
		last, _ := list.LastNonce()
		all[addr] = last + 1
	}
	pool.nonces.setAll(all)
}

// removeTx quita una tx del pool. Si estaba en pending, las posteriores
// del remitente se degradan a queue (salvo outofbound, que indica que se
// está vaciando la cola).
func (pool *TxPool) removeTx(hash types.Hash, outofbound bool) {
	tx := pool.all.Get(hash)
	if tx == nil {
		return
	}
	from, _ := pool.signer.Sender(tx) // cacheado: ya se validó
	pool.all.Remove(hash)
	if outofbound {
		pool.priced.Removed(1)
	}
	if p := pool.pending[from]; p != nil {
		if removed, invalids := p.Remove(tx); removed {
			for _, t := range invalids {
				pool.enqueue(t, from, pool.locals[from]) //nolint:errcheck
				pool.metrics.Demoted.Add(1)
			}
			pool.nonces.setIfLower(from, tx.Nonce)
			if p.Empty() {
				delete(pool.pending, from)
			}
			return
		}
	}
	if q := pool.queue[from]; q != nil {
		q.Remove(tx)
		if q.Empty() {
			delete(pool.queue, from)
			delete(pool.beats, from)
		}
	}
}

// Remove quita transacciones por hash (p. ej. inválidas al construir).
func (pool *TxPool) Remove(hashes ...types.Hash) {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	for _, h := range hashes {
		pool.removeTx(h, true)
	}
}

// Reset adapta el pool a una nueva cabecera canónica y su estado.
func (pool *TxPool) Reset(head *types.Header, state StateReader) {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	pool.setHead(head, state)
	pool.demoteUnexecutables()
	pool.promoteExecutables(nil)
	pool.truncatePending()
}

// truncatePending aplica la capacidad global de pending quitando las de
// nonce más alto de las cuentas remotas con más txs que AccountSlots.
func (pool *TxPool) truncatePending() {
	total := 0
	for _, l := range pool.pending {
		total += l.Len()
	}
	if total <= pool.config.GlobalSlots {
		return
	}
	addrs := make([]types.Address, 0, len(pool.pending))
	for a, l := range pool.pending {
		if !pool.locals[a] && l.Len() > pool.config.AccountSlots {
			addrs = append(addrs, a)
		}
	}
	sort.Slice(addrs, func(i, j int) bool { return pool.pending[addrs[i]].Len() > pool.pending[addrs[j]].Len() })
	for _, a := range addrs {
		for total > pool.config.GlobalSlots && pool.pending[a].Len() > pool.config.AccountSlots {
			last, _ := pool.pending[a].LastNonce()
			pool.removeTx(pool.pending[a].Get(last).Hash(), true)
			pool.metrics.Evicted.Add(1)
			total--
		}
	}
}

// EvictStale aplica el desalojo por antigüedad.
func (pool *TxPool) EvictStale(now time.Time) int {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	return pool.evictStale(now)
}

// Get devuelve una transacción del pool.
func (pool *TxPool) Get(h types.Hash) *types.Transaction { return pool.all.Get(h) }

// Has informa si el pool contiene la transacción.
func (pool *TxPool) Has(h types.Hash) bool { return pool.all.Get(h) != nil }

// Nonce devuelve el nonce pendiente de una cuenta.
func (pool *TxPool) Nonce(addr types.Address) uint64 {
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	return pool.nonces.get(addr)
}

// Stats devuelve (pendientes, en cola).
func (pool *TxPool) Stats() (int, int) {
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	p, q := 0, 0
	for _, l := range pool.pending {
		p += l.Len()
	}
	for _, l := range pool.queue {
		q += l.Len()
	}
	return p, q
}

// Pending devuelve las ejecutables por cuenta. Con enforceFees se corta
// cada lista en la primera tx que no cubre la base fee prevista o paga
// menos propina que el mínimo.
func (pool *TxPool) Pending(enforceFees bool) map[types.Address][]*types.Transaction {
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	out := make(map[types.Address][]*types.Transaction, len(pool.pending))
	for addr, l := range pool.pending {
		txs := l.Flatten()
		if enforceFees {
			for i, tx := range txs {
				tip, ok := EffectiveTip(tx, pool.baseFee)
				if !ok || (!pool.locals[addr] && tip.Lt(pool.config.MinTip)) {
					txs = txs[:i]
					break
				}
			}
		}
		if len(txs) > 0 {
			out[addr] = txs
		}
	}
	return out
}

// Content devuelve copias de pending y queue (inspección/RPC).
func (pool *TxPool) Content() (pending, queued map[types.Address][]*types.Transaction) {
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	pending = make(map[types.Address][]*types.Transaction, len(pool.pending))
	for a, l := range pool.pending {
		pending[a] = l.Flatten()
	}
	queued = make(map[types.Address][]*types.Transaction, len(pool.queue))
	for a, l := range pool.queue {
		queued[a] = l.Flatten()
	}
	return pending, queued
}

// Select devuelve las transacciones que cumplen f.
func (pool *TxPool) Select(f SelectFunc) []*types.Transaction {
	pending, queued := pool.Content()
	var out []*types.Transaction
	for _, m := range []map[types.Address][]*types.Transaction{pending, queued} {
		for from, txs := range m {
			for _, tx := range txs {
				if f(tx, from) {
					out = append(out, tx)
				}
			}
		}
	}
	return out
}

// Iterator devuelve el iterador ordenado para construir un bloque.
func (pool *TxPool) Iterator() *TransactionsByPriceAndNonce {
	return NewTransactionsByPriceAndNonce(pool.Pending(true), pool.BaseFee(), pool.all.Seen)
}

// String resume el pool.
func (pool *TxPool) String() string {
	p, q := pool.Stats()
	return fmt.Sprintf("TxPool{pending=%d queued=%d baseFee=%s}", p, q, pool.BaseFee())
}
