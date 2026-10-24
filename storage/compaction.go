package storage

// Compactación periódica en segundo plano.
//
// Los LSM (Pebble) compactan solos, pero tras borrados masivos (poda de
// estado, Rewind, poda de checkpoints) el espacio no se recupera hasta que
// las tombstones se compactan. El Compactor lanza una compactación
// completa cada cierto intervalo o bajo demanda, sin solapar ejecuciones.

import (
	"log/slog"
	"sync"
	"time"
)

// Compactor ejecuta compactaciones periódicas.
type Compactor struct {
	db       Compacter
	interval time.Duration
	log      *slog.Logger

	mu      sync.Mutex // serializa compactaciones
	stop    chan struct{}
	done    chan struct{}
	started bool
	// runs cuenta compactaciones realizadas.
	runs int
}

// NewCompactor crea un compactador. interval <= 0 desactiva el ciclo
// periódico (CompactNow sigue disponible). log nil usa slog.Default().
func NewCompactor(db Compacter, interval time.Duration, log *slog.Logger) *Compactor {
	if log == nil {
		log = slog.Default()
	}
	return &Compactor{db: db, interval: interval, log: log}
}

// Start arranca el ciclo periódico (idempotente).
func (c *Compactor) Start() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.started || c.interval <= 0 {
		return
	}
	c.started = true
	c.stop, c.done = make(chan struct{}), make(chan struct{})
	go c.loop(c.stop, c.done)
}

// loop es la gorutina del ciclo.
func (c *Compactor) loop(stop, done chan struct{}) {
	defer close(done)
	t := time.NewTicker(c.interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			if err := c.CompactNow(); err != nil {
				c.log.Warn("compactación fallida", "err", err)
			}
		case <-stop:
			return
		}
	}
}

// Stop detiene el ciclo y espera a que termine la compactación en curso.
func (c *Compactor) Stop() {
	c.mu.Lock()
	if !c.started {
		c.mu.Unlock()
		return
	}
	c.started = false
	stop, done := c.stop, c.done
	c.mu.Unlock()
	close(stop)
	<-done
}

// CompactNow compacta todo el rango de claves de forma síncrona.
func (c *Compactor) CompactNow() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	start := time.Now()
	if err := c.db.Compact(nil, nil); err != nil {
		return err
	}
	c.runs++
	c.log.Debug("compactación completada", "duración", time.Since(start), "n", c.runs)
	return nil
}

// Runs devuelve cuántas compactaciones se han hecho.
func (c *Compactor) Runs() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.runs
}
