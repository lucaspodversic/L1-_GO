package tests

import (
	"path/filepath"
	"testing"

	"github.com/l1/l1/node"
)

func TestCLIKeysAndInit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "k.key")
	if code := node.Main([]string{"keys", "new-secp", path}); code != 0 {
		t.Fatalf("new-secp %d", code)
	}
	if code := node.Main([]string{"keys", "inspect", path}); code != 0 {
		t.Fatalf("inspect %d", code)
	}
	if code := node.Main([]string{
		"init", "--datadir", dir, "--dev",
		"--listen", "127.0.0.1:0", "--rpc", "127.0.0.1:0", "--ws", "127.0.0.1:0",
	}); code != 0 {
		t.Fatalf("init %d", code)
	}
}
