package execution

// Este archivo define el sistema de trazado de la VM: un conjunto de
// ganchos (Hooks) que la EVM invoca en momentos clave, y dos trazadores
// listos para usar:
//
//   - StructLogger: registra cada instrucción ejecutada (pc, opcode, gas,
//     coste, profundidad, pila opcional), al estilo de debug_traceTransaction.
//   - CallTracer: reconstruye el árbol de llamadas (CALL/CREATE/...), con
//     entradas, salidas, gas usado y errores, al estilo de "callTracer".
//
// Los ganchos son opcionales: un campo nil simplemente no se invoca, así
// que el coste de no trazar es una comparación con nil.

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/l1/l1/types"
)

// Hooks agrupa los ganchos de trazado.
type Hooks struct {
	// OnTxStart se invoca antes de ejecutar una transacción.
	OnTxStart func(evm *EVM, tx *types.Transaction, from types.Address)
	// OnTxEnd se invoca al terminar (receipt nil si la tx era inválida).
	OnTxEnd func(receipt *types.Receipt, err error)
	// OnEnter se invoca al entrar en un marco de llamada o creación.
	OnEnter func(depth int, typ OpCode, from, to types.Address, input []byte, gas uint64, value *Word)
	// OnExit se invoca al salir de un marco.
	OnExit func(depth int, output []byte, gasUsed uint64, err error, reverted bool)
	// OnOpcode se invoca antes de ejecutar cada instrucción (ya cobrado su gas).
	OnOpcode func(pc uint64, op OpCode, gas, cost uint64, scope *ScopeContext, rData []byte, depth int, err error)
	// OnLog se invoca al emitir un log.
	OnLog func(l *types.Log)
}

// ---------------------------------------------------------------------------
// StructLogger
// ---------------------------------------------------------------------------

// StructLog es una entrada del registro de instrucciones.
type StructLog struct {
	Pc      uint64   `json:"pc"`
	Op      string   `json:"op"`
	Gas     uint64   `json:"gas"`
	GasCost uint64   `json:"gasCost"`
	Depth   int      `json:"depth"`
	Stack   []string `json:"stack,omitempty"`
	MemSize int      `json:"memSize"`
}

// StructLoggerConfig controla el detalle del registro.
type StructLoggerConfig struct {
	// EnableStack copia la pila en cada paso (caro).
	EnableStack bool
	// Limit acota el número de entradas (0 = sin límite).
	Limit int
}

// StructLogger acumula StructLog por cada instrucción.
type StructLogger struct {
	cfg     StructLoggerConfig
	logs    []StructLog
	output  []byte
	err     error
	gasUsed uint64
}

// NewStructLogger crea el registrador.
func NewStructLogger(cfg StructLoggerConfig) *StructLogger { return &StructLogger{cfg: cfg} }

// Hooks devuelve los ganchos que alimentan al registrador.
func (l *StructLogger) Hooks() *Hooks {
	return &Hooks{
		OnOpcode: func(pc uint64, op OpCode, gas, cost uint64, scope *ScopeContext, _ []byte, depth int, _ error) {
			if l.cfg.Limit != 0 && len(l.logs) >= l.cfg.Limit {
				return
			}
			entry := StructLog{Pc: pc, Op: op.String(), Gas: gas, GasCost: cost, Depth: depth, MemSize: len(scope.MemoryData())}
			if l.cfg.EnableStack {
				data := scope.StackData()
				entry.Stack = make([]string, len(data))
				for i := range data {
					entry.Stack[i] = data[i].Hex()
				}
			}
			l.logs = append(l.logs, entry)
		},
		OnExit: func(depth int, output []byte, gasUsed uint64, err error, _ bool) {
			if depth == 0 { // fin del marco raíz
				l.output, l.err, l.gasUsed = append([]byte(nil), output...), err, gasUsed
			}
		},
	}
}

// StructLogs devuelve las entradas registradas.
func (l *StructLogger) StructLogs() []StructLog { return l.logs }

// Output devuelve la salida, el error y el gas del marco raíz.
func (l *StructLogger) Output() ([]byte, error, uint64) { return l.output, l.err, l.gasUsed } //nolint:staticcheck

// String vuelca el registro en formato legible.
func (l *StructLogger) String() string {
	var b strings.Builder
	for _, e := range l.logs {
		fmt.Fprintf(&b, "%3d pc=%05d %-14s gas=%d cost=%d\n", e.Depth, e.Pc, e.Op, e.Gas, e.GasCost)
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// CallTracer
// ---------------------------------------------------------------------------

// CallFrame es un nodo del árbol de llamadas.
type CallFrame struct {
	Type    string         `json:"type"`
	From    types.Address  `json:"from"`
	To      types.Address  `json:"to"`
	Value   string         `json:"value,omitempty"`
	Gas     uint64         `json:"gas"`
	GasUsed uint64         `json:"gasUsed"`
	Input   types.HexBytes `json:"input"`
	Output  types.HexBytes `json:"output,omitempty"`
	Error   string         `json:"error,omitempty"`
	Revert  string         `json:"revertReason,omitempty"`
	Logs    []*types.Log   `json:"logs,omitempty"`
	Calls   []*CallFrame   `json:"calls,omitempty"`
	parent  *CallFrame     `json:"-"`
}

// CallTracer reconstruye el árbol de llamadas de una transacción.
type CallTracer struct {
	root    *CallFrame
	current *CallFrame
	// WithLogs adjunta los logs al marco que los emitió.
	WithLogs bool
}

// NewCallTracer crea el trazador.
func NewCallTracer(withLogs bool) *CallTracer { return &CallTracer{WithLogs: withLogs} }

// Hooks devuelve los ganchos del trazador de llamadas.
func (t *CallTracer) Hooks() *Hooks {
	return &Hooks{
		OnEnter: func(_ int, typ OpCode, from, to types.Address, input []byte, gas uint64, value *Word) {
			f := &CallFrame{Type: typ.String(), From: from, To: to, Gas: gas, Input: append([]byte(nil), input...)}
			if value != nil && !value.IsZero() {
				f.Value = value.Hex()
			}
			if t.current == nil {
				t.root = f
			} else {
				f.parent = t.current
				t.current.Calls = append(t.current.Calls, f)
			}
			t.current = f
		},
		OnExit: func(_ int, output []byte, gasUsed uint64, err error, reverted bool) {
			f := t.current
			if f == nil {
				return
			}
			f.GasUsed = gasUsed
			f.Output = append([]byte(nil), output...)
			if err != nil {
				f.Error = err.Error()
				if reverted {
					if r, ok := UnpackRevert(output); ok {
						f.Revert = r
					}
				}
			}
			if f.parent != nil {
				t.current = f.parent
			}
		},
		OnLog: func(l *types.Log) {
			if t.WithLogs && t.current != nil {
				t.current.Logs = append(t.current.Logs, l)
			}
		},
	}
}

// Result devuelve la raíz del árbol (nil si no se ejecutó nada).
func (t *CallTracer) Result() *CallFrame { return t.root }

// JSON serializa el árbol.
func (t *CallTracer) JSON() ([]byte, error) { return json.MarshalIndent(t.root, "", "  ") }

// MuxHooks combina varios Hooks en uno que los invoca en orden.
func MuxHooks(hs ...*Hooks) *Hooks {
	m := &Hooks{}
	m.OnTxStart = func(evm *EVM, tx *types.Transaction, from types.Address) {
		for _, h := range hs {
			if h.OnTxStart != nil {
				h.OnTxStart(evm, tx, from)
			}
		}
	}
	m.OnTxEnd = func(r *types.Receipt, err error) {
		for _, h := range hs {
			if h.OnTxEnd != nil {
				h.OnTxEnd(r, err)
			}
		}
	}
	m.OnEnter = func(d int, typ OpCode, from, to types.Address, in []byte, gas uint64, v *Word) {
		for _, h := range hs {
			if h.OnEnter != nil {
				h.OnEnter(d, typ, from, to, in, gas, v)
			}
		}
	}
	m.OnExit = func(d int, out []byte, used uint64, err error, rev bool) {
		for _, h := range hs {
			if h.OnExit != nil {
				h.OnExit(d, out, used, err, rev)
			}
		}
	}
	m.OnOpcode = func(pc uint64, op OpCode, gas, cost uint64, s *ScopeContext, rd []byte, d int, err error) {
		for _, h := range hs {
			if h.OnOpcode != nil {
				h.OnOpcode(pc, op, gas, cost, s, rd, d, err)
			}
		}
	}
	m.OnLog = func(l *types.Log) {
		for _, h := range hs {
			if h.OnLog != nil {
				h.OnLog(l)
			}
		}
	}
	return m
}
