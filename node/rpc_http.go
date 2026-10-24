package node

// Transporte HTTP para JSON-RPC.

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"time"
)

// HTTPServer sirve JSON-RPC sobre HTTP.
type HTTPServer struct {
	rpc *RPCServer
	srv *http.Server
	ln  net.Listener
}

// NewHTTPServer crea el servidor.
func NewHTTPServer(rpc *RPCServer, addr string) *HTTPServer {
	h := &HTTPServer{rpc: rpc}
	mux := http.NewServeMux()
	mux.HandleFunc("/", h.serve)
	mux.HandleFunc("/health", h.health)
	h.srv = &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	return h
}

// Start escucha en segundo plano.
func (h *HTTPServer) Start() error {
	ln, err := net.Listen("tcp", h.srv.Addr)
	if err != nil {
		return err
	}
	h.ln = ln
	go h.srv.Serve(ln)
	return nil
}

// Addr dirección efectiva.
func (h *HTTPServer) Addr() string {
	if h.ln == nil {
		return h.srv.Addr
	}
	return h.ln.Addr().String()
}

// Stop cierra.
func (h *HTTPServer) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return h.srv.Shutdown(ctx)
}

func (h *HTTPServer) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "solo POST", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 5<<20))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	out := h.rpc.HandleRaw(r.Context(), body)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	_, _ = w.Write(out)
}

func (h *HTTPServer) health(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var st HealthStatus
	if h.rpc.node != nil && h.rpc.node.health != nil {
		st = h.rpc.node.health.Status()
	}
	_ = json.NewEncoder(w).Encode(st)
}
