package tests

// Mocks ligeros para Broadcaster y StateReader usados en pruebas aisladas.

import (
	"sync"
	"testing"

	"github.com/l1/l1/types"
)

// mockBroadcaster acumula mensajes de consenso sin red.
type mockBroadcaster struct {
	mu   sync.Mutex
	Msgs [][]byte
}

func (m *mockBroadcaster) Broadcast(msg []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Msgs = append(m.Msgs, append([]byte(nil), msg...))
	return nil
}

func (m *mockBroadcaster) SendTo(_ types.Address, msg []byte) error { return m.Broadcast(msg) }

func (m *mockBroadcaster) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.Msgs)
}

func TestMockBroadcaster(t *testing.T) {
	m := &mockBroadcaster{}
	_ = m.Broadcast([]byte("a"))
	_ = m.SendTo(types.Address{}, []byte("b"))
	if m.Len() != 2 {
		t.Fatal(m.Len())
	}
}
