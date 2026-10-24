package node

// Bus de eventos pub/sub tipado débilmente (topic → callbacks).

import "sync"

// EventBus difunde eventos nombrados.
type EventBus struct {
	mu   sync.RWMutex
	subs map[string][]chan any
}

// NewEventBus crea el bus.
func NewEventBus() *EventBus {
	return &EventBus{subs: make(map[string][]chan any)}
}

// Subscribe registra un canal (buffer 16) para topic; devuelve unsub.
func (b *EventBus) Subscribe(topic string) (<-chan any, func()) {
	ch := make(chan any, 16)
	b.mu.Lock()
	b.subs[topic] = append(b.subs[topic], ch)
	b.mu.Unlock()
	unsub := func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		list := b.subs[topic]
		for i, c := range list {
			if c == ch {
				b.subs[topic] = append(list[:i], list[i+1:]...)
				close(ch)
				return
			}
		}
	}
	return ch, unsub
}

// Publish envía v a todos los subscriptores (no bloquea si el buffer está lleno).
func (b *EventBus) Publish(topic string, v any) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, ch := range b.subs[topic] {
		select {
		case ch <- v:
		default:
		}
	}
}

// Topics de eventos conocidos.
const (
	EventNewHead     = "newHead"
	EventFinalized   = "finalized"
	EventNewTx       = "newTx"
	EventPeerAdded   = "peerAdded"
	EventPeerRemoved = "peerRemoved"
)
