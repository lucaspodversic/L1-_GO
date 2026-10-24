package tests

// Scripts de arranque / parada de testnet (bash embebido).

import (
	"os"
	"path/filepath"
)

const startTestnetSh = `#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
if [[ ! -f config/genesis.json ]]; then
  echo "falta config/genesis.json — ejecuta el generador Go WriteTestnetGenesis"
  exit 1
fi
docker compose up -d
echo "testnet arriba; RPC en localhost:8545"
`

const stopTestnetSh = `#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
docker compose down
`

// WriteTestnetScripts escribe start.sh y stop.sh ejecutables.
func WriteTestnetScripts(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for name, body := range map[string]string{"start.sh": startTestnetSh, "stop.sh": stopTestnetSh} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
			return err
		}
	}
	return nil
}
