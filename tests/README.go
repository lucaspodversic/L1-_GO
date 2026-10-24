// Package tests agrupa las pruebas de integración, fuzz, benches y utilidades
// del nodo L1, junto con generadores de activos de testnet y documentación.
//
// # Cómo ejecutar
//
//	go test ./tests/ -count=1
//	go test ./tests/ -short          # omite integraciones largas
//	go test ./tests/ -run Int -timeout 120s
//	go test ./tests/ -fuzz=FuzzCodec -fuzztime=5s
//	go test ./tests/ -bench=. -benchmem
//
// # Generar activos de testnet / CI
//
//	go test ./tests/ -run TestWriteTestnetAssets -args -write
//
// o bien desde código:
//
//	tests.WriteAllTestnetAssets("/ruta/deploy")
//
// # Estructura
//
//   - *_test.go          — unitarias por dominio
//   - int_*.go           — escenarios de integración (invocados vía TestInt*)
//   - fuzz_*.go          — núcleos de fuzz (expuestos como Fuzz* en utils_test.go)
//   - bench_*.go         — núcleos de benchmark
//   - testnet_*.go       — génesis, docker-compose y scripts
//   - README.go          — este documento (como comentario de paquete)
//   - docs_architecture.go — visión de arquitectura embebida
package tests

// ReadmeMarkdown es el README del directorio tests en Markdown (español).
const ReadmeMarkdown = `# Tests del L1

Suite de pruebas del cliente L1 (Jolteon + EVM + P2P).

## Comandos útiles

` + "```" + `bash
go test ./tests/ -count=1
go test ./tests/ -short
go test ./tests/ -run 'TestInt' -timeout 180s
go test ./tests/ -fuzz=FuzzTrie -fuzztime=10s
go test ./tests/ -bench=BenchmarkTrie -benchmem
` + "```" + `

## Integraciones

| Test | Qué valida |
|------|------------|
| IntSingleNode | finalización solo + RPC |
| IntFourNodes | quórum 4 validadores |
| IntSyncNewNode | sync de cabeceras/cuerpos |
| IntPartition | tolerancia a partición breve |
| IntValidatorRotation | cambio de época / set |
| IntReorg | preferencia 2-chain |
| IntTxFlow | envío y recepción de txs |
| IntContractDeploy | CREATE + código |
| IntRestartRecovery | WAL + reinicio |

Los escenarios viven en ` + "`int_*.go`" + ` y se exponen como ` + "`TestInt*`" + ` en ` + "`utils_test.go`" + `.
`

// EnsureReadmeDocumented evita que el compilador elimine el const si nadie lo lee.
func EnsureReadmeDocumented() string { return ReadmeMarkdown }
