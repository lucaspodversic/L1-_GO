package tests

import (
	"testing"

	"github.com/l1/l1/consensus"
	"github.com/l1/l1/types"
)

func TestSlashingEquivocationDetect(t *testing.T) {
	tr := consensus.NewEquivocationTracker(types.DevnetChainID)
	// Sin votos reales: sólo smoke de construcción.
	if tr == nil {
		t.Fatal("nil")
	}
}
