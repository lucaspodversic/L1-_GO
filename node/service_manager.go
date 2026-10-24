package node

// ServiceManager arranca/detiene servicios en orden (LIFO al parar).

import (
	"fmt"
	"sync"
)

// Lifecycle es un servicio con Start/Stop.
type Lifecycle interface {
	Start() error
	Stop() error
}

// named envuelve un Lifecycle con nombre.
type named struct {
	name string
	svc  Lifecycle
}

// ServiceManager ordena el ciclo de vida.
type ServiceManager struct {
	mu      sync.Mutex
	list    []named
	started []named
	log     *Logger
}

// NewServiceManager crea el gestor.
func NewServiceManager(log *Logger) *ServiceManager {
	if log == nil {
		log = DefaultLogger()
	}
	return &ServiceManager{log: log}
}

// Register añade un servicio (aún no arrancado).
func (m *ServiceManager) Register(name string, svc Lifecycle) {
	m.mu.Lock()
	m.list = append(m.list, named{name, svc})
	m.mu.Unlock()
}

// StartAll arranca en orden de registro.
func (m *ServiceManager) StartAll() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, n := range m.list {
		m.log.Infof("arrancando %s", n.name)
		if err := n.svc.Start(); err != nil {
			m.stopLocked()
			return fmt.Errorf("node: arrancar %s: %w", n.name, err)
		}
		m.started = append(m.started, n)
	}
	return nil
}

// StopAll detiene en orden inverso.
func (m *ServiceManager) StopAll() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stopLocked()
}

func (m *ServiceManager) stopLocked() error {
	var first error
	for i := len(m.started) - 1; i >= 0; i-- {
		n := m.started[i]
		m.log.Infof("deteniendo %s", n.name)
		if err := n.svc.Stop(); err != nil && first == nil {
			first = err
		}
	}
	m.started = nil
	return first
}

// LifecycleFunc adapta funciones a Lifecycle.
type LifecycleFunc struct {
	StartFunc func() error
	StopFunc  func() error
}

func (l LifecycleFunc) Start() error {
	if l.StartFunc != nil {
		return l.StartFunc()
	}
	return nil
}
func (l LifecycleFunc) Stop() error {
	if l.StopFunc != nil {
		return l.StopFunc()
	}
	return nil
}
