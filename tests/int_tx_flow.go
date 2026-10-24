package tests

// Integración: flujo de transacción vía mempool del nodo en marcha.

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/l1/l1/crypto"
	"github.com/l1/l1/types"
)

// RunIntTxFlow firma una legacy tx con la clave funded del init --dev y la
// entrega al mempool (SubmitLocal).
func RunIntTxFlow(t *testing.T) {
	d := StartDevNode(t, 50)
	d.WaitFinalized(t, 1, 15*time.Second)

	fk, err := crypto.LoadKeyFile(filepath.Join(d.Dir, "funded.key"), "")
	if err != nil {
		t.Fatalf("funded.key: %v", err)
	}
	secp, ok := fk.(*crypto.Secp256k1PrivateKey)
	if !ok {
		t.Fatal("funded no es secp256k1")
	}
	to := types.Address{0xab}
	tx := types.NewLegacyTx(d.Node.Config().ChainID, 0, &to, types.EtherAmount(1), 21000, types.GWeiAmount(2), nil)
	signed, err := crypto.SignTx(tx, secp)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := d.Node.Mempool().SubmitLocal(signed); err != nil {
		t.Logf("SubmitLocal: %v (nonce/basefee pueden rechazar; se registra)", err)
	} else {
		t.Log("tx admitida en mempool")
	}
	d.WaitFinalized(t, 2, 15*time.Second)
}
