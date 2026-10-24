package tests

import (
	"path/filepath"
	"testing"

	"github.com/l1/l1/node"
)

func TestConfigDefaultAndLoad(t *testing.T) {
	cfg := node.DefaultConfig()
	if cfg.BlockTimeMs <= 0 {
		t.Fatal("block time")
	}
	path := filepath.Join(t.TempDir(), "config.json")
	cfg.BlockTimeMs = 123
	cfg.LogLevel = "error"
	if err := node.SaveConfigFile(path, cfg); err != nil {
		t.Fatal(err)
	}
	loaded, err := node.LoadConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.BlockTimeMs != 123 {
		t.Fatalf("got %d", loaded.BlockTimeMs)
	}
}
