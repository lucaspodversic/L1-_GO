# Arquitectura L1

## Capas

1. **types** — primitivas (Address, Hash, Amount, Header, Block, Tx, Genesis, RLP).
2. **crypto** — Keccak/BLAKE3/SHA256, secp256k1, Ed25519, BLS12-381, VRF, Merkle RFC6962, keystore.
3. **storage** — Pebble KV, MPT hexario, StateDB con journal/snapshots, BlockStore.
4. **execution** — EVM (opcodes, gas, precompiles), BlockProcessor, fee market.
5. **mempool** — pool por precio/nonce, reemplazo, evicción.
6. **consensus** — Jolteon 2-chain, QC/TC, pacemaker, safety rules, épocas, slashing.
7. **p2p** — TCP + X25519/Ed25519 handshake, ChaCha20-Poly1305, Kademlia, gossip, sync.
8. **node** — builder, CLI, JSON-RPC HTTP/WS, métricas, health, apagado ordenado.

## Consenso (Jolteon)

- Vista = ronda; líder vía VRF ponderado.
- Quórum ⌊2N/3⌋+1. N=1 auto-completa QC/TC (devnet).
- Finalidad 2-chain: commit del abuelo al formar QC del hijo.
- Pacemaker con backoff; timeouts producen TC y avance de vista.
- SafetyRules + WAL impiden doble voto / equivocación local.

## Flujo de un bloque

Pacemaker OnNewView → líder propone → votos → QC → Insert árbol →
FinalityTracker → onCommit → StateDB/canonical → gossip → RPC newHeads.

## P2P

Handshake mutua autenticación; PeerID = Keccak(Ed25519 pub).
Canales: gossip (txs/bloques/consenso), req/resp (headers/bodies/state), ping.
Sync: status → headers → bodies → state nodes.

## Ejecución

EVM compatible con opcodes Shanghai-ish; precompiles 1–9; CREATE/CREATE2;
snapshots StateDB para REVERT; IntrinsicGas + fee market EIP-1559.
