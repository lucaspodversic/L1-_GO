package tests

import (
	"testing"

	"github.com/l1/l1/execution"
)

func TestGasIntrinsic(t *testing.T) {
	g, err := execution.IntrinsicGas(nil, nil, false)
	if err != nil || g < 21000 {
		t.Fatalf("%d %v", g, err)
	}
	g2, err := execution.IntrinsicGas([]byte{1, 2, 3}, nil, true)
	if err != nil || g2 <= g {
		t.Fatalf("create gas %d vs %d", g2, g)
	}
}
