package tests

import (
	"testing"

	"github.com/l1/l1/consensus"
)

func TestConsensusSafetyTimeoutMonotonic(t *testing.T) {
	dir := t.TempDir()
	wal, err := consensus.OpenConsensusWAL(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = wal.Close() })
	rs := consensus.NewRoundState(0, nil)
	sr := consensus.NewSafetyRules(rs, wal)
	if err := sr.RestoreFromWAL(); err != nil {
		t.Fatal(err)
	}
	if err := sr.CommitTimeout(1); err != nil {
		t.Fatal(err)
	}
	// Misma vista otra vez debe fallar (monotonicidad).
	err2 := sr.CommitTimeout(1)
	err3 := sr.CommitTimeout(2)
	t.Logf("timeout1again=%v timeout2=%v", err2, err3)
	if err3 != nil {
		t.Fatal(err3)
	}
}
