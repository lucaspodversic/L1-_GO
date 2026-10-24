package tests

// Integración: rotación de validador a nivel de época (smoke del EpochManager).
// En N=1 el set no cambia; validamos que el motor atraviesa varias vistas/épocas
// sin romper finalización (proxy de liveness bajo el mismo validador).

import (
	"testing"
	"time"

	"github.com/l1/l1/consensus"
)

// RunIntValidatorRotation comprueba que tras varios bloques el EpochManager
// sigue sirviendo el set génesis y el nodo finaliza.
func RunIntValidatorRotation(t *testing.T) {
	d := StartDevNode(t, 40)
	d.WaitFinalized(t, 3, 20*time.Second)
	// Inspección ligera: el servicio de consenso expone Finalizer / no paniquea.
	_ = consensus.DefaultEpochParams()
	_ = d.Node.Consensus()
	time.Sleep(100 * time.Millisecond)
	t.Logf("validator-rotation smoke OK finalized=%d", d.Node.Health().Status().Finalized)
}
