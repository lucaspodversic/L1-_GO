package p2p

// Transporte TCP con handshake autenticado y tramas cifradas.

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// Conn es una conexión autenticada ya negociada.
type Conn struct {
	raw    net.Conn
	keys   *SessionKeys
	remote PeerID
	mu     sync.Mutex
}

// RemoteID es el PeerID del otro extremo.
func (c *Conn) RemoteID() PeerID { return c.remote }

// RemoteAddr es la dirección de red.
func (c *Conn) RemoteAddr() net.Addr { return c.raw.RemoteAddr() }

// Send escribe una trama cifrada.
func (c *Conn) Send(payload []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return WriteFrame(c.raw, c.keys, payload)
}

// Receive lee la siguiente trama.
func (c *Conn) Receive() ([]byte, error) {
	return ReadFrame(c.raw, c.keys)
}

// Close cierra la conexión subyacente.
func (c *Conn) Close() error { return c.raw.Close() }

// SetDeadline propaga el deadline.
func (c *Conn) SetDeadline(t time.Time) error { return c.raw.SetDeadline(t) }

// Transport escucha y diala conexiones autenticadas.
type Transport struct {
	id       *LocalIdentity
	listener net.Listener
	mu       sync.Mutex
	closed   bool
}

// NewTransport crea un transporte con la identidad dada.
func NewTransport(id *LocalIdentity) *Transport {
	return &Transport{id: id}
}

// Identity expone la identidad local.
func (t *Transport) Identity() *LocalIdentity { return t.id }

// Listen arranca el aceptador TCP en addr (host:port).
func (t *Transport) Listen(addr string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.listener != nil {
		return fmt.Errorf("p2p: ya escuchando")
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	t.listener = ln
	return nil
}

// Addr devuelve la dirección de escucha.
func (t *Transport) Addr() net.Addr {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.listener == nil {
		return nil
	}
	return t.listener.Addr()
}

// Accept espera una conexión entrante y completa el handshake.
func (t *Transport) Accept() (*Conn, error) {
	t.mu.Lock()
	ln := t.listener
	t.mu.Unlock()
	if ln == nil {
		return nil, fmt.Errorf("p2p: no escuchando")
	}
	raw, err := ln.Accept()
	if err != nil {
		return nil, err
	}
	hs, err := DoHandshake(raw, t.id, false)
	if err != nil {
		raw.Close()
		return nil, err
	}
	return &Conn{raw: raw, keys: hs.Keys, remote: hs.RemoteID}, nil
}

// Dial conecta a addr y completa el handshake (como iniciador).
func (t *Transport) Dial(ctx context.Context, addr string) (*Conn, error) {
	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	hs, err := DoHandshake(raw, t.id, true)
	if err != nil {
		raw.Close()
		return nil, err
	}
	return &Conn{raw: raw, keys: hs.Keys, remote: hs.RemoteID}, nil
}

// Close detiene el listener.
func (t *Transport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	if t.listener != nil {
		err := t.listener.Close()
		t.listener = nil
		return err
	}
	return nil
}
