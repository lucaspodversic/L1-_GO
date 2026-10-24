package node

// Errores JSON-RPC 2.0.

import "fmt"

// RPCError es un error con código JSON-RPC.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func (e *RPCError) Error() string { return fmt.Sprintf("rpc %d: %s", e.Code, e.Message) }

// Constructores habituales.
func ErrParse() *RPCError          { return &RPCError{Code: -32700, Message: "parse error"} }
func ErrInvalidRequest() *RPCError { return &RPCError{Code: -32600, Message: "invalid request"} }
func ErrMethodNotFound(m string) *RPCError {
	return &RPCError{Code: -32601, Message: "method not found: " + m}
}
func ErrInvalidParams(msg string) *RPCError {
	return &RPCError{Code: -32602, Message: msg}
}
func ErrInternal(msg string) *RPCError {
	return &RPCError{Code: -32603, Message: msg}
}
func ErrServer(code int, msg string) *RPCError {
	return &RPCError{Code: code, Message: msg}
}
