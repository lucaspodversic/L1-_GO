package p2p

// Capa request/response con correlador de IDs y timeouts.

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Pending espera una respuesta.
type Pending struct {
	ch chan []byte
}

// ReqResp gestiona peticiones.
type ReqResp struct {
	mu      sync.Mutex
	pending map[uint64]*Pending
	next    atomic.Uint64
	send    func(id PeerID, msg []byte) error
	timeout time.Duration
}

// NewReqResp crea la capa.
func NewReqResp(send func(PeerID, []byte) error, timeout time.Duration) *ReqResp {
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	return &ReqResp{pending: make(map[uint64]*Pending), send: send, timeout: timeout}
}

// Request envía una petición y espera la respuesta.
func (r *ReqResp) Request(to PeerID, payload []byte) ([]byte, error) {
	id := r.next.Add(1)
	p := &Pending{ch: make(chan []byte, 1)}
	r.mu.Lock()
	r.pending[id] = p
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(r.pending, id)
		r.mu.Unlock()
	}()
	msg := EncodeApp(AppReq, EncodeReq(id, payload))
	if err := r.send(to, msg); err != nil {
		return nil, err
	}
	select {
	case resp := <-p.ch:
		return resp, nil
	case <-time.After(r.timeout):
		return nil, fmt.Errorf("p2p: timeout req %d", id)
	}
}

// HandleReq procesa una petición entrante y envía la respuesta via handler.
func (r *ReqResp) HandleReq(from PeerID, payload []byte, handler func([]byte) []byte) {
	id, body, err := DecodeReq(payload)
	if err != nil {
		return
	}
	resp := handler(body)
	msg := EncodeApp(AppResp, EncodeReq(id, resp))
	_ = r.send(from, msg)
}

// HandleResp entrega una respuesta al waiter.
func (r *ReqResp) HandleResp(payload []byte) {
	id, body, err := DecodeReq(payload)
	if err != nil {
		return
	}
	r.mu.Lock()
	p := r.pending[id]
	r.mu.Unlock()
	if p != nil {
		select {
		case p.ch <- body:
		default:
		}
	}
}
