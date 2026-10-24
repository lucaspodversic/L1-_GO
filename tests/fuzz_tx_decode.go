package tests

// Fuzz de decodificación de transacciones RLP.

import (
	"testing"

	"github.com/l1/l1/types"
)

func fuzzTxDecode(f *testing.F) {
	to := types.Address{1}
	tx := types.NewLegacyTx(types.DevnetChainID, 0, &to, types.EtherAmount(1), 21000, types.GWeiAmount(1), []byte{1, 2})
	if b, err := tx.MarshalBinary(); err == nil {
		f.Add(b)
	}
	f.Add([]byte{0xc0})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = types.DecodeTransaction(data)
	})
}
