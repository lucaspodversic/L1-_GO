package consensus

// Este archivo decide quién es el líder (proponente) de cada vista. La
// elección debe ser determinista (todos los validadores deben coincidir sin
// comunicarse) y conocida de antemano (los votos se envían al líder de la
// vista siguiente). Se ofrecen dos estrategias:
//
//   - RoundRobinElector: índice = vista mod n. Simple y equitativa en número
//     de turnos, pero ignora el stake.
//   - WeightedElector (por defecto): muestrea un punto uniforme en
//     [0, poder total) a partir de Keccak(semilla de época ‖ vista) y elige
//     al validador cuyo intervalo acumulado lo contiene. Cada validador
//     lidera una fracción de vistas proporcional a su poder, y la semilla
//     (derivada de VRF) impide predecir el calendario más allá de la época.

import (
	"encoding/binary"

	"github.com/l1/l1/crypto"
	"github.com/l1/l1/types"
)

// LeaderElector elige el líder de una vista dentro de una época.
type LeaderElector interface {
	Leader(info *EpochInfo, view uint64) *Validator
}

// RoundRobinElector rota por orden de dirección.
type RoundRobinElector struct{}

// Leader implementa LeaderElector.
func (RoundRobinElector) Leader(info *EpochInfo, view uint64) *Validator {
	set := info.Validators
	return set.ByIndex(int(view % uint64(set.Size())))
}

// WeightedElector elige ponderando por poder de voto.
type WeightedElector struct{}

// Leader implementa LeaderElector.
func (WeightedElector) Leader(info *EpochInfo, view uint64) *Validator {
	set := info.Validators
	target := crypto.VRFSelect(LeaderSeed(info.Seed, view), set.TotalPower())
	var acc uint64
	for _, v := range set.vals {
		acc += v.Power
		if target < acc {
			return v
		}
	}
	return set.vals[len(set.vals)-1] // inalcanzable: target < total
}

// LeaderSeed deriva el material aleatorio de una vista.
func LeaderSeed(seed types.Hash, view uint64) types.Hash {
	var v [8]byte
	binary.BigEndian.PutUint64(v[:], view)
	return crypto.Keccak256Hash([]byte("l1/leader"), seed[:], v[:])
}

// IsLeader informa si addr lidera la vista.
func IsLeader(el LeaderElector, info *EpochInfo, view uint64, addr types.Address) bool {
	l := el.Leader(info, view)
	return l != nil && l.Address == addr
}
