package tests

// Punto de entrada Test/Fuzz/Benchmark que enlaza con int_*, fuzz_*, bench_*.
// También vuelca activos de testnet cuando se pasa -args write (vía env).

import (
	"os"
	"testing"
)

func TestIntSingleNode(t *testing.T)        { RunIntSingleNode(t) }
func TestIntFourNodes(t *testing.T)         { RunIntFourNodes(t) }
func TestIntSyncNewNode(t *testing.T)       { RunIntSyncNewNode(t) }
func TestIntPartition(t *testing.T)         { RunIntPartition(t) }
func TestIntValidatorRotation(t *testing.T) { RunIntValidatorRotation(t) }
func TestIntReorg(t *testing.T)             { RunIntReorg(t) }
func TestIntTxFlow(t *testing.T)            { RunIntTxFlow(t) }
func TestIntContractDeploy(t *testing.T)    { RunIntContractDeploy(t) }
func TestIntRestartRecovery(t *testing.T)   { RunIntRestartRecovery(t) }

func FuzzCodec(f *testing.F)       { fuzzCodec(f) }
func FuzzVM(f *testing.F)          { fuzzVM(f) }
func FuzzTrie(f *testing.F)        { fuzzTrie(f) }
func FuzzP2PMessages(f *testing.F) { fuzzP2PMessages(f) }
func FuzzTxDecode(f *testing.F)    { fuzzTxDecode(f) }

func BenchmarkTrie(b *testing.B)      { benchTrie(b) }
func BenchmarkVM(b *testing.B)        { benchVM(b) }
func BenchmarkConsensus(b *testing.B) { benchConsensus(b) }
func BenchmarkMempool(b *testing.B)   { benchMempool(b) }
func BenchmarkSync(b *testing.B)      { benchSync(b) }

// TestWriteTestnetAssets genera deploy/ si L1_WRITE_ASSETS=1.
func TestWriteTestnetAssets(t *testing.T) {
	if os.Getenv("L1_WRITE_ASSETS") != "1" {
		t.Skip("set L1_WRITE_ASSETS=1 para volcar activos")
	}
	dir := "/workspace/l1/deploy"
	if err := WriteAllTestnetAssets(dir); err != nil {
		t.Fatal(err)
	}
	t.Logf("activos en %s", dir)
}

func TestDocsEmbedded(t *testing.T) {
	if len(EnsureReadmeDocumented()) < 100 || len(ArchitectureDoc()) < 100 {
		t.Fatal("docs cortos")
	}
}
