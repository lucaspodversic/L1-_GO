package node

// Servidor JSON-RPC: registro de métodos y despacho (sin transporte).

import (
	"context"
	"encoding/json"
	"sync"
)

// RPCHandler maneja un método.
type RPCHandler func(ctx context.Context, params json.RawMessage) (any, error)

// RPCServer registra y despacha métodos.
type RPCServer struct {
	mu      sync.RWMutex
	methods map[string]RPCHandler
	node    *Node
	subs    *SubscriptionManager
}

// NewRPCServer crea el servidor ligado al nodo.
func NewRPCServer(n *Node) *RPCServer {
	s := &RPCServer{methods: make(map[string]RPCHandler), node: n}
	s.subs = NewSubscriptionManager(n)
	registerEthBlocks(s)
	registerEthTx(s)
	registerEthState(s)
	registerNet(s)
	registerAdmin(s)
	registerSubscriptions(s)
	return s
}

// Register añade un método.
func (s *RPCServer) Register(name string, h RPCHandler) {
	s.mu.Lock()
	s.methods[name] = h
	s.mu.Unlock()
}

// Methods lista nombres registrados.
func (s *RPCServer) Methods() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.methods))
	for k := range s.methods {
		out = append(out, k)
	}
	return out
}

// Handle procesa una petición ya decodificada.
func (s *RPCServer) Handle(ctx context.Context, req RPCRequest) RPCResponse {
	if s.node != nil && s.node.metrics != nil {
		s.node.metrics.RPCRequests.Add(1)
	}
	resp := RPCResponse{JSONRPC: "2.0", ID: req.ID}
	if req.JSONRPC != "2.0" || req.Method == "" {
		resp.Error = ErrInvalidRequest()
		return resp
	}
	s.mu.RLock()
	h := s.methods[req.Method]
	s.mu.RUnlock()
	if h == nil {
		resp.Error = ErrMethodNotFound(req.Method)
		return resp
	}
	res, err := h(ctx, req.Params)
	if err != nil {
		if re, ok := err.(*RPCError); ok {
			resp.Error = re
		} else {
			resp.Error = ErrInternal(err.Error())
		}
		return resp
	}
	resp.Result = res
	if resp.Result == nil {
		resp.Result = json.RawMessage("null")
	}
	return resp
}

// HandleRaw decodifica (single o batch) y responde JSON.
func (s *RPCServer) HandleRaw(ctx context.Context, body []byte) []byte {
	trim := trimSpace(body)
	if len(trim) > 0 && trim[0] == '[' {
		var reqs []RPCRequest
		if err := json.Unmarshal(trim, &reqs); err != nil {
			out, _ := json.Marshal(RPCResponse{JSONRPC: "2.0", Error: ErrParse()})
			return out
		}
		resps := make([]RPCResponse, len(reqs))
		for i, r := range reqs {
			resps[i] = s.Handle(ctx, r)
		}
		out, _ := json.Marshal(resps)
		return out
	}
	var req RPCRequest
	if err := json.Unmarshal(trim, &req); err != nil {
		out, _ := json.Marshal(RPCResponse{JSONRPC: "2.0", Error: ErrParse()})
		return out
	}
	out, _ := json.Marshal(s.Handle(ctx, req))
	return out
}

func trimSpace(b []byte) []byte {
	i, j := 0, len(b)
	for i < j && (b[i] == ' ' || b[i] == '\n' || b[i] == '\t' || b[i] == '\r') {
		i++
	}
	for j > i && (b[j-1] == ' ' || b[j-1] == '\n' || b[j-1] == '\t' || b[j-1] == '\r') {
		j--
	}
	return b[i:j]
}

// parseParams decodifica params como array posicional.
func parseParams(raw json.RawMessage, out ...any) error {
	if len(raw) == 0 {
		return nil
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil {
		return ErrInvalidParams("params debe ser un array")
	}
	for i := range out {
		if i >= len(arr) {
			break
		}
		if err := json.Unmarshal(arr[i], out[i]); err != nil {
			return ErrInvalidParams(err.Error())
		}
	}
	return nil
}
