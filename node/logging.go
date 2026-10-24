package node

// Logging estructurado mínimo (stdlib log + niveles).

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
)

// Level de log.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	}
	return "?"
}

// Logger con nivel.
type Logger struct {
	mu    sync.Mutex
	level Level
	l     *log.Logger
}

// NewLogger crea un logger hacia w.
func NewLogger(w io.Writer, level Level) *Logger {
	if w == nil {
		w = os.Stderr
	}
	return &Logger{level: level, l: log.New(w, "", log.LstdFlags|log.Lmicroseconds)}
}

// DefaultLogger a stderr nivel Info.
func DefaultLogger() *Logger { return NewLogger(os.Stderr, LevelInfo) }

// SetLevel cambia el nivel.
func (l *Logger) SetLevel(level Level) { l.mu.Lock(); l.level = level; l.mu.Unlock() }

func (l *Logger) logf(level Level, format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if level < l.level {
		return
	}
	l.l.Printf("[%s] %s", level, fmt.Sprintf(format, args...))
}

func (l *Logger) Debugf(f string, a ...any) { l.logf(LevelDebug, f, a...) }
func (l *Logger) Infof(f string, a ...any)  { l.logf(LevelInfo, f, a...) }
func (l *Logger) Warnf(f string, a ...any)  { l.logf(LevelWarn, f, a...) }
func (l *Logger) Errorf(f string, a ...any) { l.logf(LevelError, f, a...) }

// ParseLevel interpreta "debug"/"info"/...
func ParseLevel(s string) Level {
	switch strings.ToLower(s) {
	case "debug":
		return LevelDebug
	case "warn", "warning":
		return LevelWarn
	case "error":
		return LevelError
	default:
		return LevelInfo
	}
}
