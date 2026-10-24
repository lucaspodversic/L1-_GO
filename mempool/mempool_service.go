package mempool

// Este archivo envuelve el TxPool en un servicio con ciclo de vida:
//
//   - Un bucle propio procesa las nuevas cabeceras (Reset del pool) sin
//     bloquear a quien las notifica, desaloja periódicamente las colas
//     inactivas y publica las métricas de tamaño.
//   - Difunde las transacciones nuevas a los suscriptores (la capa P2P
//     las reenviará a los pares; la RPC las expone por websocket).
//   - Expone el iterador para el constructor de bloques.

import (
	"errors"
	"sync"
	"time"

	"github.com/l1/l1/execution"
	"github.com/l1/l1/types"
)

// ChainSource da acceso a la cabecera actual y su estado.
type ChainSource interface {
	CurrentHeader() *types.Header
	StateAt(root types.Hash) (StateReader, error)
}

// ServiceConfig configura el servicio.
type ServiceConfig struct {
	EvictInterval time.Duration // cada cuánto revisar colas inactivas
	HeadBuffer    int           // cabeceras pendientes de procesar
}

// Service es el mempool con ciclo de vida.
type Service struct {
	pool  *TxPool
	chain ChainSource
	cfg   ServiceConfig

	heads chan *types.Header
	quit  chan struct{}
	wg    sync.WaitGroup

	subMu  sync.Mutex
	subs   map[int]chan<- []*types.Transaction
	nextID int

	startOnce, stopOnce sync.Once
}

// ErrServiceStopped se devuelve al operar con el servicio detenido.
var ErrServiceStopped = errors.New("servicio de mempool detenido")

// NewService crea el servicio.
func NewService(pool *TxPool, chain ChainSource, cfg ServiceConfig) *Service {
	if cfg.EvictInterval <= 0 {
		cfg.EvictInterval = time.Minute
	}
	if cfg.HeadBuffer <= 0 {
		cfg.HeadBuffer = 16
	}
	return &Service{pool: pool, chain: chain, cfg: cfg, heads: make(chan *types.Header, cfg.HeadBuffer),
		quit: make(chan struct{}), subs: map[int]chan<- []*types.Transaction{}}
}

// Pool devuelve el pool subyacente.
func (s *Service) Pool() *TxPool { return s.pool }

// Start arranca el bucle.
func (s *Service) Start() {
	s.startOnce.Do(func() {
		s.wg.Add(1)
		go s.loop()
	})
}

// Stop detiene el bucle y espera a que termine.
func (s *Service) Stop() {
	s.stopOnce.Do(func() { close(s.quit) })
	s.wg.Wait()
}

// loop procesa cabeceras y desalojos.
func (s *Service) loop() {
	defer s.wg.Done()
	t := time.NewTicker(s.cfg.EvictInterval)
	defer t.Stop()
	for {
		select {
		case h := <-s.heads:
			// Si llegaron varias, sólo importa la última.
		drain:
			for {
				select {
				case h2 := <-s.heads:
					h = h2
				default:
					break drain
				}
			}
			s.resetTo(h)
		case now := <-t.C:
			s.pool.EvictStale(now)
		case <-s.quit:
			return
		}
	}
}

// resetTo abre el estado de h y resetea el pool.
func (s *Service) resetTo(h *types.Header) {
	if s.chain == nil {
		return
	}
	st, err := s.chain.StateAt(h.StateRoot)
	if err != nil {
		return // estado no disponible (podado): se esperará a otra cabecera
	}
	s.pool.Reset(h, st)
}

// NotifyNewHead informa de una nueva cabecera canónica (no bloquea).
func (s *Service) NotifyNewHead(h *types.Header) {
	select {
	case s.heads <- h:
	default:
		// Buffer lleno: descartamos la más antigua para hacer sitio.
		select {
		case <-s.heads:
		default:
		}
		select {
		case s.heads <- h:
		default:
		}
	}
}

// ResetSync aplica una cabecera de forma síncrona (pruebas/arranque).
func (s *Service) ResetSync(h *types.Header) { s.resetTo(h) }

// Submit añade transacciones y difunde las aceptadas.
func (s *Service) Submit(txs []*types.Transaction, local bool) []error {
	select {
	case <-s.quit:
		errs := make([]error, len(txs))
		for i := range errs {
			errs[i] = ErrServiceStopped
		}
		return errs
	default:
	}
	errs := s.pool.Add(txs, local)
	var accepted []*types.Transaction
	for i, err := range errs {
		if err == nil {
			accepted = append(accepted, txs[i])
		}
	}
	if len(accepted) > 0 {
		s.broadcast(accepted)
	}
	return errs
}

// SubmitLocal añade una transacción local.
func (s *Service) SubmitLocal(tx *types.Transaction) error {
	return s.Submit([]*types.Transaction{tx}, true)[0]
}

// broadcast entrega a los suscriptores sin bloquear (los lentos pierden).
func (s *Service) broadcast(txs []*types.Transaction) {
	s.subMu.Lock()
	defer s.subMu.Unlock()
	for _, ch := range s.subs {
		select {
		case ch <- txs:
		default:
		}
	}
}

// SubscribeNewTxs registra un canal; devuelve la función de baja.
func (s *Service) SubscribeNewTxs(ch chan<- []*types.Transaction) (unsubscribe func()) {
	s.subMu.Lock()
	id := s.nextID
	s.nextID++
	s.subs[id] = ch
	s.subMu.Unlock()
	return func() {
		s.subMu.Lock()
		delete(s.subs, id)
		s.subMu.Unlock()
	}
}

// Iterator devuelve el iterador para el constructor de bloques.
func (s *Service) Iterator() execution.TxIterator { return s.pool.Iterator() }

// Stats devuelve métricas con tamaños actuales.
func (s *Service) Stats() MetricsSnapshot {
	snap := s.pool.Metrics().Snapshot()
	snap.Pending, snap.Queued = s.pool.Stats()
	return snap
}
