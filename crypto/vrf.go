package crypto

// VRF (Verifiable Random Function) basada en firmas BLS.
//
// Una VRF da a cada validador un número pseudoaleatorio que sólo él puede
// calcular (necesita su clave secreta) pero que cualquiera puede verificar
// con su clave pública. La usamos para:
//   - la aleatoriedad del bloque (campo Header.Random / PREVRANDAO), y
//   - la elección de líder ponderada por stake cuando se habilite.
//
// Construcción: las firmas BLS son deterministas y ÚNICAS (para una clave
// pública válida y un mensaje sólo existe una firma válida), lo que las
// convierte en una VRF:
//
//   π = BLS_Sign(sk, α) con DST propio de la VRF
//   β = SHA-256("l1/vrf/output/v1" || π)
//
// Verificar es comprobar la firma π y recalcular β. Las propiedades de
// unicidad y pseudoaleatoriedad se heredan de BLS bajo el supuesto co-CDH.
// Se usa un DST distinto al de las firmas de consenso, de modo que una firma
// de voto nunca pueda reutilizarse como prueba VRF.

import (
	"encoding/binary"
	"math/big"

	"github.com/l1/l1/types"
)

// VRFProofSize es el tamaño de la prueba π (una firma BLS comprimida).
const VRFProofSize = BLSSignatureSize

// dstVRF es el DST de hash-to-curve exclusivo de la VRF.
var dstVRF = []byte("L1_VRF_BLS12381G2_XMD:SHA-256_SSWU_RO_")

// vrfOutputPrefix separa el dominio del hash de salida.
var vrfOutputPrefix = []byte("l1/vrf/output/v1")

// VRFProve calcula (β, π) para la entrada alpha.
func VRFProve(sk *BLSPrivateKey, alpha []byte) (beta types.Hash, proof []byte, err error) {
	sig, err := sk.SignDST(alpha, dstVRF)
	if err != nil {
		return types.Hash{}, nil, err
	}
	proof = sig.Bytes()
	return vrfOutput(proof), proof, nil
}

// VRFVerify comprueba la prueba π de pk sobre alpha y devuelve β si es válida.
func VRFVerify(pk *BLSPublicKey, alpha, proof []byte) (types.Hash, bool) {
	sig, err := BLSSignatureFromBytes(proof)
	if err != nil {
		return types.Hash{}, false
	}
	if !pk.VerifyDST(alpha, sig, dstVRF) {
		return types.Hash{}, false
	}
	return vrfOutput(proof), true
}

// VRFProofToHash deriva β de una prueba ya verificada.
func VRFProofToHash(proof []byte) types.Hash { return vrfOutput(proof) }

// vrfOutput calcula β = SHA-256(prefijo || π).
func vrfOutput(proof []byte) types.Hash {
	return types.Hash(Sha256(vrfOutputPrefix, proof))
}

// VRFInput construye la entrada canónica α para una ronda de consenso:
// chainID || epoch || view || semilla previa. Así cada (época, vista) tiene
// una salida distinta e impredecible hasta que la semilla anterior se fija.
func VRFInput(chainID types.ChainID, epoch, view uint64, prevRandom types.Hash) []byte {
	out := make([]byte, 0, 24+32)
	out = binary.BigEndian.AppendUint64(out, uint64(chainID))
	out = binary.BigEndian.AppendUint64(out, epoch)
	out = binary.BigEndian.AppendUint64(out, view)
	return append(out, prevRandom[:]...)
}

// VRFSelect mapea β a un entero uniforme en [0, n). Con 256 bits de entrada
// el sesgo del módulo es < n/2^256, despreciable. Útil para elegir líder en
// [0, stakeTotal) y buscar luego el validador por suma acumulada.
func VRFSelect(beta types.Hash, n uint64) uint64 {
	if n == 0 {
		return 0
	}
	v := new(big.Int).SetBytes(beta[:])
	return v.Mod(v, new(big.Int).SetUint64(n)).Uint64()
}

// VRFBelowThreshold implementa sortición criptográfica: devuelve true si
// β/2^256 < stake/totalStake, es decir, si el validador "gana" la lotería con
// probabilidad proporcional a su stake. Se evalúa con aritmética entera exacta.
func VRFBelowThreshold(beta types.Hash, stake, totalStake uint64) bool {
	if totalStake == 0 || stake == 0 {
		return false
	}
	if stake >= totalStake {
		return true
	}
	// β · total < stake · 2^256
	lhs := new(big.Int).SetBytes(beta[:])
	lhs.Mul(lhs, new(big.Int).SetUint64(totalStake))
	rhs := new(big.Int).Lsh(new(big.Int).SetUint64(stake), 256)
	return lhs.Cmp(rhs) < 0
}
