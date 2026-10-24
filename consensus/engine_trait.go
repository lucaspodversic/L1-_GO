// Package consensus implementa el motor de consenso BFT de la cadena, de la
// familia HotStuff (variante de compromiso en dos cadenas al estilo
// Jolteon/DiemBFT v4):
//
//   - Un conjunto de validadores ponderado por stake (validator_set.go)
//     derivado del contrato de staking nativo (staking.go) en cada cambio de
//     época (epoch.go).
//   - En cada vista hay un único líder (leader_election.go) que propone un
//     bloque (proposal.go) que extiende el bloque certificado más alto que
//     conoce (fork_choice.go).
//   - Los validadores votan (vote.go) con firmas BLS; 2f+1 de poder de voto
//     forman un Quorum Certificate agregado (quorum_cert.go) que viaja en el
//     campo Justify del siguiente bloque.
//   - Si la vista no progresa, el pacemaker (pacemaker.go) dispara timeouts
//     (timeouts.go); 2f+1 timeouts forman un Timeout Certificate
//     (view_change.go) que permite avanzar de vista sin QC.
//   - Regla de compromiso de dos cadenas (finality.go): un bloque B es final
//     cuando su hijo directo B' (vista de B' = vista de B + 1) obtiene un QC.
//   - Recompensas (rewards.go) y slashing por doble voto (slashing.go) se
//     aplican sobre el estado mediante el gancho execution.Finalizer y un
//     contrato de sistema de evidencias.
//
// Este archivo declara las interfaces que el motor expone al resto del nodo
// y las que necesita de él (lectura de la cadena, red).
package consensus

import (
	"errors"

	"github.com/l1/l1/execution"
	"github.com/l1/l1/types"
)

// Errores generales del paquete.
var (
	// ErrUnknownParent: el padre del bloque/propuesta no se conoce.
	ErrUnknownParent = errors.New("consenso: padre desconocido")
	// ErrUnknownEpoch: no se dispone del conjunto de validadores de la época.
	ErrUnknownEpoch = errors.New("consenso: época desconocida")
	// ErrNotValidator: el firmante no pertenece al conjunto de validadores.
	ErrNotValidator = errors.New("consenso: no es validador")
	// ErrInvalidSignature: firma BLS inválida.
	ErrInvalidSignature = errors.New("consenso: firma inválida")
	// ErrStaleView: el mensaje es de una vista antigua.
	ErrStaleView = errors.New("consenso: vista obsoleta")
)

// ChainReader es la vista de sólo lectura de la cadena que necesita el
// consenso (la implementa storage.BlockStore o la blockchain del nodo).
type ChainReader interface {
	// CurrentHeader devuelve la cabecera de la punta de la cadena.
	CurrentHeader() *types.Header
	// HeaderByNumber devuelve la cabecera canónica de una altura.
	HeaderByNumber(number uint64) (*types.Header, error)
	// HeaderByHash devuelve una cabecera por su hash.
	HeaderByHash(hash types.Hash) (*types.Header, error)
}

// Broadcaster es la interfaz mínima de red que usa el motor: difusión a
// todos los validadores y envío directo a uno (p. ej. el voto al próximo
// líder). Los mensajes ya van codificados (consensus_msgs.go).
type Broadcaster interface {
	Broadcast(msg []byte) error
	SendTo(validator types.Address, msg []byte) error
}

// ValidatorSetProvider resuelve el conjunto de validadores de una época;
// lo usan la validación de QCs (que pueden pertenecer a la época anterior)
// y la distribución de recompensas.
type ValidatorSetProvider interface {
	ValidatorSet(epoch uint64) (*ValidatorSet, error)
}

// ValidatorSetFunc adapta una función a ValidatorSetProvider.
type ValidatorSetFunc func(epoch uint64) (*ValidatorSet, error)

// ValidatorSet implementa ValidatorSetProvider.
func (f ValidatorSetFunc) ValidatorSet(epoch uint64) (*ValidatorSet, error) { return f(epoch) }

// Engine es el contrato que cumple un motor de consenso completo. Separa
// las responsabilidades "puras" (verificar cabeceras y bloques, preparar
// cabeceras) del bucle de protocolo (Start/Stop/HandleMessage), de modo que
// la sincronización pueda reutilizar la validación sin arrancar el motor.
type Engine interface {
	// Author devuelve la dirección del proponente del bloque.
	Author(header *types.Header) (types.Address, error)
	// VerifyHeader comprueba las reglas de consenso de una cabecera
	// respecto a su padre.
	VerifyHeader(chain ChainReader, header *types.Header) error
	// VerifyBlock comprueba cabecera, cuerpo y el QC justificativo de un
	// bloque ya comprometido (usado al sincronizar).
	VerifyBlock(chain ChainReader, block *types.Block) error
	// Prepare rellena los campos de consenso (época, vista, hash del
	// conjunto de validadores, aleatoriedad) de una cabecera a proponer.
	Prepare(chain ChainReader, header *types.Header) error
	// Finalizer devuelve el gancho que aplica recompensas/penalizaciones
	// al final de cada bloque durante la ejecución.
	Finalizer() execution.Finalizer
	// HandleMessage procesa un mensaje de consenso recibido de la red.
	HandleMessage(from types.Address, msg []byte) error
	// Start arranca el bucle de protocolo; Stop lo detiene.
	Start() error
	Stop() error
}

// CommitHandler recibe los bloques que acaban de volverse finales, en orden
// ascendente de altura, junto con el QC que provocó el compromiso.
type CommitHandler func(blocks []*types.Block, qc *QuorumCert)
