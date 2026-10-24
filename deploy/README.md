# Tests del L1

Suite de pruebas del cliente L1 (Jolteon + EVM + P2P).

## Comandos útiles

```bash
go test ./tests/ -count=1
go test ./tests/ -short
go test ./tests/ -run 'TestInt' -timeout 180s
go test ./tests/ -fuzz=FuzzTrie -fuzztime=10s
go test ./tests/ -bench=BenchmarkTrie -benchmem
```

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

Los escenarios viven en `int_*.go` y se exponen como `TestInt*` en `utils_test.go`.
