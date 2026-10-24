package node

// Subscripciones JSON-RPC (eth_subscribe / eth_unsubscribe) sobre WebSocket.

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
)

// sessionKey marca la sesión WS en el context.
type sessionKey struct{}

func withSession(ctx context.Context, s *WSSession) context.Context {
	return context.WithValue(ctx, sessionKey{}, s)
}

func sessionFrom(ctx context.Context) *WSSession {
	v, _ := ctx.Value(sessionKey{}).(*WSSession)
	return v
}

// SubscriptionManager crea sesiones.
type SubscriptionManager struct {
	node *Node
}

// NewSubscriptionManager crea el gestor.
func NewSubscriptionManager(n *Node) *SubscriptionManager {
	return &SubscriptionManager{node: n}
}

// NewSession crea una sesión ligada a un escritor WS.
func (m *SubscriptionManager) NewSession(write func([]byte) error) *WSSession {
	return &WSSession{node: m.node, write: write, subs: make(map[string]*subscription)}
}

// WSSession mantiene subscripciones de una conexión.
type WSSession struct {
	node  *Node
	write func([]byte) error
	mu    sync.Mutex
	subs  map[string]*subscription
	next  atomic.Uint64
}

type subscription struct {
	id     string
	topic  string
	unsub  func()
	cancel context.CancelFunc
}

// Close cancela todas.
func (s *WSSession) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, sub := range s.subs {
		sub.cancel()
		if sub.unsub != nil {
			sub.unsub()
		}
		delete(s.subs, id)
	}
}

func (s *WSSession) add(topic string, ch <-chan any, unsub func()) string {
	id := fmt.Sprintf("0x%x", s.next.Add(1))
	ctx, cancel := context.WithCancel(context.Background())
	sub := &subscription{id: id, topic: topic, unsub: unsub, cancel: cancel}
	s.mu.Lock()
	s.subs[id] = sub
	s.mu.Unlock()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case v, ok := <-ch:
				if !ok {
					return
				}
				notif := map[string]any{
					"jsonrpc": "2.0",
					"method":  "eth_subscription",
					"params": map[string]any{
						"subscription": id,
						"result":       v,
					},
				}
				b, _ := json.Marshal(notif)
				_ = s.write(b)
			}
		}
	}()
	return id
}

func (s *WSSession) remove(id string) bool {
	s.mu.Lock()
	sub, ok := s.subs[id]
	if ok {
		delete(s.subs, id)
	}
	s.mu.Unlock()
	if !ok {
		return false
	}
	sub.cancel()
	if sub.unsub != nil {
		sub.unsub()
	}
	return true
}

func registerSubscriptions(s *RPCServer) {
	s.Register("eth_subscribe", s.ethSubscribe)
	s.Register("eth_unsubscribe", s.ethUnsubscribe)
}

func (s *RPCServer) ethSubscribe(ctx context.Context, params json.RawMessage) (any, error) {
	sess := sessionFrom(ctx)
	if sess == nil {
		return nil, ErrServer(-32000, "eth_subscribe requiere WebSocket")
	}
	var name string
	if err := parseParams(params, &name); err != nil {
		return nil, err
	}
	var topic string
	switch name {
	case "newHeads":
		topic = EventNewHead
	case "newPendingTransactions":
		topic = EventNewTx
	default:
		return nil, ErrInvalidParams("suscripción desconocida: " + name)
	}
	ch, unsub := s.node.bus.Subscribe(topic)
	id := sess.add(topic, ch, unsub)
	return id, nil
}

func (s *RPCServer) ethUnsubscribe(ctx context.Context, params json.RawMessage) (any, error) {
	sess := sessionFrom(ctx)
	if sess == nil {
		return false, nil
	}
	var id string
	if err := parseParams(params, &id); err != nil {
		return nil, err
	}
	return sess.remove(id), nil
}
