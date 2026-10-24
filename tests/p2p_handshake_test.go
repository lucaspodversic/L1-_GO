package tests

import (
	"context"
	"testing"
	"time"

	"github.com/l1/l1/p2p"
)

func TestP2PHandshakeEncrypted(t *testing.T) {
	a, err := p2p.NewLocalIdentity()
	if err != nil {
		t.Fatal(err)
	}
	b, err := p2p.NewLocalIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ta := p2p.NewTransport(a)
	tb := p2p.NewTransport(b)
	if err := ta.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ta.Close() })
	errCh := make(chan error, 1)
	go func() {
		c, err := ta.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer c.Close()
		errCh <- c.Send([]byte("hola"))
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := tb.Dial(ctx, ta.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	msg, err := c.Receive()
	if err != nil || string(msg) != "hola" {
		t.Fatalf("%q %v", msg, err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}
