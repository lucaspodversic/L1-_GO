package tests

// Herramienta de carga: genera N transacciones firmadas y las envía por HTTP JSON-RPC.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/l1/l1/crypto"
	"github.com/l1/l1/types"
)

// LoadTestConfig configura una ráfaga de envío.
type LoadTestConfig struct {
	RPCURL   string
	Key      *crypto.Secp256k1PrivateKey
	ChainID  types.ChainID
	Count    int
	To       types.Address
	GasPrice types.Amount
}

// RunLoadTest firma y envía Count transacciones eth_sendRawTransaction.
// Devuelve el número de éxitos y el último error.
func RunLoadTest(cfg LoadTestConfig) (ok int, lastErr error) {
	if cfg.Count <= 0 {
		cfg.Count = 10
	}
	if cfg.GasPrice.IsZero() {
		cfg.GasPrice = types.GWeiAmount(2)
	}
	client := &http.Client{Timeout: 5 * time.Second}
	for i := 0; i < cfg.Count; i++ {
		tx := types.NewLegacyTx(cfg.ChainID, uint64(i), &cfg.To, types.NewAmount(1), 21000, cfg.GasPrice, nil)
		signed, err := crypto.SignTx(tx, cfg.Key)
		if err != nil {
			lastErr = err
			continue
		}
		raw, err := signed.MarshalBinary()
		if err != nil {
			lastErr = err
			continue
		}
		payload, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0", "id": i + 1, "method": "eth_sendRawTransaction",
			"params": []string{"0x" + hex.EncodeToString(raw)},
		})
		resp, err := client.Post(cfg.RPCURL, "application/json", bytes.NewReader(payload))
		if err != nil {
			lastErr = err
			continue
		}
		var out struct {
			Error any `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		resp.Body.Close()
		if out.Error != nil {
			lastErr = fmt.Errorf("%v", out.Error)
			continue
		}
		ok++
	}
	return ok, lastErr
}
