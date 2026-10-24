package execution

// Este archivo implementa el precompilado ECRECOVER (0x01): dada una firma
// ECDSA secp256k1 (hash, v, r, s) devuelve la dirección del firmante
// rellenada a 32 bytes, o una salida vacía si la firma no es válida. Nunca
// falla con error: una firma inválida no consume todo el gas.

import (
	"github.com/l1/l1/crypto"
	"github.com/l1/l1/types"
)

// EcrecoverGas es el coste fijo del precompilado.
const EcrecoverGas uint64 = 3000

type ecrecover struct{}

// RequiredGas es constante.
func (c *ecrecover) RequiredGas([]byte) uint64 { return EcrecoverGas }

// Run decodifica hash(32) || v(32) || r(32) || s(32), rellenando con ceros
// si la entrada es más corta.
func (c *ecrecover) Run(input []byte) ([]byte, error) {
	in := getData(input, 0, 128)
	// v debe ser 27 ó 28 codificado en 32 bytes (los 31 primeros a cero).
	for _, b := range in[32:63] {
		if b != 0 {
			return nil, nil
		}
	}
	v := in[63]
	if v != 27 && v != 28 {
		return nil, nil
	}
	var sig types.Signature
	copy(sig[0:32], in[64:96])   // r
	copy(sig[32:64], in[96:128]) // s
	sig[64] = v - 27
	h := types.BytesToHash(in[0:32])
	// crypto.Ecrecover valida r,s en [1, n-1] (sin exigir s bajo, como el
	// precompilado de Ethereum) y devuelve la clave sin comprimir.
	pub, err := crypto.Ecrecover(h, sig)
	if err != nil || len(pub) != 65 {
		return nil, nil
	}
	addr := types.BytesToAddress(types.Keccak256(pub[1:])[12:])
	return leftPad32(addr[:]), nil
}
