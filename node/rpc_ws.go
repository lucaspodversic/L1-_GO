package node

// WebSocket RFC 6455 mínimo (sin extensiones) para JSON-RPC + subscripciones.

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// WSServer sirve JSON-RPC sobre WebSocket.
type WSServer struct {
	rpc *RPCServer
	srv *http.Server
	ln  net.Listener
}

// NewWSServer crea el servidor.
func NewWSServer(rpc *RPCServer, addr string) *WSServer {
	s := &WSServer{rpc: rpc}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.upgrade)
	s.srv = &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	return s
}

// Start escucha.
func (s *WSServer) Start() error {
	ln, err := net.Listen("tcp", s.srv.Addr)
	if err != nil {
		return err
	}
	s.ln = ln
	go s.srv.Serve(ln)
	return nil
}

// Addr dirección efectiva.
func (s *WSServer) Addr() string {
	if s.ln == nil {
		return s.srv.Addr
	}
	return s.ln.Addr().String()
}

// Stop cierra.
func (s *WSServer) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.srv.Shutdown(ctx)
}

func (s *WSServer) upgrade(w http.ResponseWriter, r *http.Request) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		http.Error(w, "se requiere websocket", http.StatusBadRequest)
		return
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		http.Error(w, "falta Sec-WebSocket-Key", http.StatusBadRequest)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack no soportado", http.StatusInternalServerError)
		return
	}
	conn, buf, err := hj.Hijack()
	if err != nil {
		return
	}
	h := sha1.Sum([]byte(key + wsGUID))
	accept := base64.StdEncoding.EncodeToString(h[:])
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
	if _, err := buf.WriteString(resp); err != nil {
		conn.Close()
		return
	}
	if err := buf.Flush(); err != nil {
		conn.Close()
		return
	}
	ws := &wsConn{conn: conn, r: buf.Reader}
	go s.serveConn(ws)
}

type wsConn struct {
	conn net.Conn
	r    *bufio.Reader
	wmu  sync.Mutex
}

// WriteText envía una trama de texto (servidor: sin máscara).
func (c *wsConn) WriteText(data []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return writeWSFrame(c.conn, 0x1, data, false)
}

func (c *wsConn) Close() error {
	c.wmu.Lock()
	_ = writeWSFrame(c.conn, 0x8, nil, false)
	c.wmu.Unlock()
	return c.conn.Close()
}

func (s *WSServer) serveConn(c *wsConn) {
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sess := s.rpc.subs.NewSession(func(b []byte) error { return c.WriteText(b) })
	defer sess.Close()
	ctx = withSession(ctx, sess)
	for {
		op, payload, err := readWSFrame(c.r)
		if err != nil {
			return
		}
		switch op {
		case 0x1, 0x2:
			out := s.rpc.HandleRaw(ctx, payload)
			if err := c.WriteText(out); err != nil {
				return
			}
		case 0x8:
			return
		case 0x9: // ping
			c.wmu.Lock()
			_ = writeWSFrame(c.conn, 0xA, payload, false)
			c.wmu.Unlock()
		}
	}
}

// writeWSFrame escribe una trama FIN con opcode.
func writeWSFrame(w io.Writer, opcode byte, payload []byte, mask bool) error {
	var hdr [14]byte
	hdr[0] = 0x80 | opcode
	n := len(payload)
	i := 2
	switch {
	case n < 126:
		hdr[1] = byte(n)
	case n < 65536:
		hdr[1] = 126
		binary.BigEndian.PutUint16(hdr[2:], uint16(n))
		i = 4
	default:
		hdr[1] = 127
		binary.BigEndian.PutUint64(hdr[2:], uint64(n))
		i = 10
	}
	var key [4]byte
	if mask {
		hdr[1] |= 0x80
		_, _ = rand.Read(key[:])
		copy(hdr[i:], key[:])
		i += 4
	}
	if _, err := w.Write(hdr[:i]); err != nil {
		return err
	}
	if mask {
		masked := make([]byte, n)
		for j := range payload {
			masked[j] = payload[j] ^ key[j%4]
		}
		payload = masked
	}
	_, err := w.Write(payload)
	return err
}

// readWSFrame lee una trama (acepta máscara de cliente).
func readWSFrame(r *bufio.Reader) (byte, []byte, error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, nil, err
	}
	op := h[0] & 0x0F
	masked := h[1]&0x80 != 0
	n := uint64(h[1] & 0x7F)
	switch n {
	case 126:
		var b [2]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, nil, err
		}
		n = uint64(binary.BigEndian.Uint16(b[:]))
	case 127:
		var b [8]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, nil, err
		}
		n = binary.BigEndian.Uint64(b[:])
	}
	if n > 16<<20 {
		return 0, nil, errors.New("ws: trama demasiado grande")
	}
	var key [4]byte
	if masked {
		if _, err := io.ReadFull(r, key[:]); err != nil {
			return 0, nil, err
		}
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= key[i%4]
		}
	}
	return op, payload, nil
}

// --- cliente WS mínimo (para pruebas y CLI) ---

// WSClient es un cliente de prueba.
type WSClient struct {
	conn net.Conn
	r    *bufio.Reader
	mu   sync.Mutex
}

// DialWS conecta a ws://addr/.
func DialWS(addr string) (*WSClient, error) {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString([]byte("l1-ws-client-key"))
	req := "GET / HTTP/1.1\r\nHost: " + addr + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\nSec-WebSocket-Version: 13\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		conn.Close()
		return nil, errors.New("ws: upgrade rechazado")
	}
	return &WSClient{conn: conn, r: br}, nil
}

// Send envía texto (enmascarado como exige RFC para clientes).
func (c *WSClient) Send(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return writeWSFrame(c.conn, 0x1, data, true)
}

// Recv lee el siguiente mensaje de texto.
func (c *WSClient) Recv() ([]byte, error) {
	for {
		op, p, err := readWSFrame(c.r)
		if err != nil {
			return nil, err
		}
		if op == 0x1 || op == 0x2 {
			return p, nil
		}
		if op == 0x8 {
			return nil, io.EOF
		}
	}
}

// SetReadDeadline aplica deadline.
func (c *WSClient) SetReadDeadline(t time.Time) error { return c.conn.SetReadDeadline(t) }

// Close cierra.
func (c *WSClient) Close() error { return c.conn.Close() }
