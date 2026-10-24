package tests

import (
	"testing"
	"time"
)

// TestConsensusLivenessSingleNode usa el harness de integración (N=1).
func TestConsensusLivenessSingleNode(t *testing.T) {
	d := StartDevNode(t, 40)
	d.WaitFinalized(t, 2, 15*time.Second)
}
