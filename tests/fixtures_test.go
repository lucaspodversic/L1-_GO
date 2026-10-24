package tests

// Fixtures reutilizables: direcciones, cabeceras y bytecode de ejemplo.

import (
	"testing"

	"github.com/l1/l1/execution"
	"github.com/l1/l1/types"
)

// fixtureAddr construye una dirección determinista a partir de un byte.
func fixtureAddr(n byte) types.Address {
	return types.BytesToAddress([]byte{n})
}

// fixtureHeader devuelve una cabecera mínima para tests de EVM.
func fixtureHeader(num uint64) *types.Header {
	return &types.Header{Number: num, GasLimit: 30_000_000, BaseFee: types.GWeiAmount(1), Timestamp: num + 1}
}

// fixtureReturn5 es bytecode que calcula 2+3 y lo retorna (32 bytes).
func fixtureReturn5() []byte {
	return []byte{0x60, 2, 0x60, 3, 0x01, 0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xf3}
}

// fixtureEmptyInit es initcode que despliega código vacío.
func fixtureEmptyInit() []byte {
	return execution.Assemble(execution.PUSH1, byte(0), execution.PUSH1, byte(0), execution.RETURN)
}

func TestFixturesSmoke(t *testing.T) {
	if fixtureAddr(1).IsZero() {
		t.Fatal("addr")
	}
	if len(fixtureReturn5()) == 0 || fixtureHeader(1).GasLimit == 0 {
		t.Fatal("fixtures")
	}
	_ = fixtureEmptyInit()
}
