// Package types define las estructuras de datos fundamentales de la cadena L1:
// hashes, direcciones, montos, cabeceras de bloque, bloques, transacciones,
// firmas, recibos, cuentas, identificadores de cadena y el génesis.
//
// # Filosofía de diseño
//
// El paquete es deliberadamente "hoja": no depende de ningún otro paquete del
// proyecto (sólo de la biblioteca estándar y de golang.org/x/crypto/sha3 para
// Keccak-256). Así, criptografía, almacenamiento, VM, mempool, consenso, P2P y
// RPC pueden importarlo sin generar ciclos.
//
// # Compatibilidad con Ethereum
//
// Muchas decisiones replican las de Ethereum para poder reutilizar wallets,
// herramientas y conocimiento existente:
//
//   - Hashes de 32 bytes con Keccak-256 (el Keccak "legacy", no SHA3-256 FIPS).
//   - Direcciones de 20 bytes con checksum EIP-55.
//   - Codificación canónica RLP (ver codec.go) para hashear y persistir.
//   - Transacciones legacy con EIP-155 y transacciones tipadas EIP-1559
//     (tipo 0x02), con el mismo formato de firma y de hash de firma.
//   - Cuentas [nonce, balance, storageRoot, codeHash] y Bloom de logs de 2048 bits.
//
// # Diferencias con Ethereum
//
// La cabecera de bloque agrega campos propios del consenso BFT estilo
// HotStuff: época, vista (ronda), hash del conjunto de validadores, hash del
// Quorum Certificate (QC) que justifica al padre y un valor de aleatoriedad
// (salida VRF del proponente). El QC en sí viaja en el cuerpo del bloque como
// bytes opacos (Block.Justify) que el paquete de consenso sabe interpretar.
//
// # Raíces de Merkle
//
// Las raíces de transacciones y recibos se calculan con un Merkle Patricia
// Trie, que vive en el paquete storage. Para no importar storage desde aquí se
// usa la interfaz TrieHasher (ver block.go): el llamador inyecta la
// implementación concreta.
package types
