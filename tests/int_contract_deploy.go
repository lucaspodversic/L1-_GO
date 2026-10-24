package tests

// Integración: despliegue de contrato vía EVM Create.

import (
	"testing"

	"github.com/l1/l1/execution"
	"github.com/l1/l1/storage"
	"github.com/l1/l1/types"
)

// RunIntContractDeploy ejecuta CREATE y verifica dirección/código.
func RunIntContractDeploy(t *testing.T) {
	st, err := storage.New(types.EmptyRootHash, storage.NewMemoryStateDatabase())
	if err != nil {
		t.Fatal(err)
	}
	caller := types.Address{0xca}
	st.AddBalance(caller, types.EtherAmount(10))
	h := &types.Header{Number: 1, GasLimit: 30_000_000, BaseFee: types.GWeiAmount(1), Timestamp: 1}
	evm := execution.NewEVM(execution.NewEVMBlockContext(h, nil, nil), execution.TxContext{Origin: caller}, st, nil, execution.Config{})
	st.Prepare(caller, caller, nil, evm.ActivePrecompileAddresses(), nil)
	// initcode que retorna 32 bytes de memoria (runtime trivial).
	init := execution.Assemble(
		execution.PUSH1, byte(1), execution.PUSH1, byte(0), execution.MSTORE,
		execution.PUSH1, byte(32), execution.PUSH1, byte(0), execution.RETURN,
	)
	ret, addr, _, err := evm.Create(caller, init, 500000, execution.NewWord(0))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if addr.IsZero() {
		t.Fatal("addr cero")
	}
	code := st.GetCode(addr)
	if len(code) == 0 && len(ret) == 0 {
		t.Fatal("sin código desplegado")
	}
	t.Logf("contract deploy OK addr=%s codeLen=%d retLen=%d", addr.Hex(), len(code), len(ret))
}
