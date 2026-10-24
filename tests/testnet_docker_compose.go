package tests

// Generador de docker-compose.yml para una testnet local de 4 nodos.

import (
	"os"
	"path/filepath"
)

// DockerComposeYAML es la plantilla de compose (servicios l1-node-0..3).
const DockerComposeYAML = `version: "3.9"
services:
  l1-node-0:
    image: l1:local
    command: ["run", "--datadir", "/data", "--genesis", "/config/genesis.json", "--validator-key", "/config/validator0.key", "--listen", "0.0.0.0:30303", "--rpc", "0.0.0.0:8545", "--mine"]
    volumes:
      - ./config:/config:ro
      - node0:/data
    ports:
      - "8545:8545"
      - "30303:30303"
  l1-node-1:
    image: l1:local
    command: ["run", "--datadir", "/data", "--genesis", "/config/genesis.json", "--validator-key", "/config/validator1.key", "--bootnodes", "l1-node-0:30303", "--listen", "0.0.0.0:30303", "--rpc", "0.0.0.0:8545", "--mine"]
    volumes:
      - ./config:/config:ro
      - node1:/data
    depends_on: [l1-node-0]
  l1-node-2:
    image: l1:local
    command: ["run", "--datadir", "/data", "--genesis", "/config/genesis.json", "--validator-key", "/config/validator2.key", "--bootnodes", "l1-node-0:30303", "--listen", "0.0.0.0:30303", "--rpc", "0.0.0.0:8545", "--mine"]
    volumes:
      - ./config:/config:ro
      - node2:/data
    depends_on: [l1-node-0]
  l1-node-3:
    image: l1:local
    command: ["run", "--datadir", "/data", "--genesis", "/config/genesis.json", "--validator-key", "/config/validator3.key", "--bootnodes", "l1-node-0:30303", "--listen", "0.0.0.0:30303", "--rpc", "0.0.0.0:8545", "--mine"]
    volumes:
      - ./config:/config:ro
      - node3:/data
    depends_on: [l1-node-0]
volumes:
  node0:
  node1:
  node2:
  node3:
`

// WriteDockerCompose escribe docker-compose.yml en dir.
func WriteDockerCompose(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(DockerComposeYAML), 0o644)
}
