package node

// Apagado elegante: escucha señales OS y cancela un contexto.

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// WaitSignal bloquea hasta SIGINT/SIGTERM o cancelación del ctx.
func WaitSignal(ctx context.Context) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-ctx.Done():
	case <-ch:
	}
	signal.Stop(ch)
}

// WithShutdown crea un ctx cancelado por señal.
func WithShutdown(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	go func() {
		WaitSignal(ctx)
		cancel()
	}()
	return ctx, cancel
}
