#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
if [[ ! -f config/genesis.json ]]; then
  echo "falta config/genesis.json — ejecuta el generador Go WriteTestnetGenesis"
  exit 1
fi
docker compose up -d
echo "testnet arriba; RPC en localhost:8545"
