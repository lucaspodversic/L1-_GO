package tests

import (
	"encoding/json"
	"testing"
	"time"
)

func TestRPCEthBlockNumber(t *testing.T) {
	d := StartDevNode(t, 50)
	d.WaitFinalized(t, 1, 15*time.Second)
	raw := d.RPCCall(t, "eth_blockNumber", []any{})
	var hexNum string
	if err := json.Unmarshal(raw, &hexNum); err != nil || hexNum == "" || hexNum == "0x0" {
		t.Fatalf("%s %v", raw, err)
	}
	raw2 := d.RPCCall(t, "eth_chainId", []any{})
	t.Logf("chainId=%s block=%s", raw2, hexNum)
}
