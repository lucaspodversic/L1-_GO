package consensus

// Este archivo gestiona las épocas: tramos de EpochLength bloques durante
// los que el conjunto de validadores es fijo. El conjunto de cada época se
// deriva del estado de staking con UNA ÉPOCA DE ANTELACIÓN:
//
//	conjunto(e+2) = ValidatorSetFromState(estado tras el último bloque de e)
//
// La antelación existe porque, con compromiso en dos cadenas, el último
// bloque de una época puede no ser final todavía cuando hay que proponer el
// primero de la siguiente; derivando el conjunto de un bloque una época más
// antiguo, éste es final con total seguridad (EpochLength ≫ 2) y todos los
// nodos honestos calculan exactamente el mismo conjunto. Las épocas 0 y 1
// usan el conjunto del génesis.
//
// Cada época tiene además una semilla (para la elección de líder) que se
// deriva de la aleatoriedad VRF del mismo bloque frontera.

import (
	"encoding/binary"
	"fmt"
	"sort"
	"sync"

	"github.com/l1/l1/crypto"
	"github.com/l1/l1/execution"
	"github.com/l1/l1/types"
)

// EpochParams define la duración de las épocas.
type EpochParams struct {
	// Length es el número de bloques por época (>= 4).
	Length uint64
}

// DefaultEpochParams: 1000 bloques (≈ 1 h con bloques de ~3.6 s).
func DefaultEpochParams() EpochParams { return EpochParams{Length: 1000} }

// length devuelve la longitud saneada.
func (p EpochParams) length() uint64 {
	if p.Length < 4 {
		return 4
	}
	return p.Length
}

// EpochOf devuelve la época de una altura (el génesis es de la época 0).
func (p EpochParams) EpochOf(number uint64) uint64 { return number / p.length() }

// FirstBlock es la primera altura de la época.
func (p EpochParams) FirstBlock(epoch uint64) uint64 { return epoch * p.length() }

// LastBlock es la última altura de la época.
func (p EpochParams) LastBlock(epoch uint64) uint64 { return (epoch+1)*p.length() - 1 }

// IsLastBlock informa si number cierra su época.
func (p EpochParams) IsLastBlock(number uint64) bool { return (number+1)%p.length() == 0 }

// EpochInfo describe una época.
type EpochInfo struct {
	Epoch      uint64
	StartBlock uint64
	Validators *ValidatorSet
	// Seed alimenta la elección de líder de la época.
	Seed types.Hash
}

// EpochSeed deriva la semilla de una época a partir de la aleatoriedad del
// bloque frontera del que se deriva.
func EpochSeed(epoch uint64, random types.Hash) types.Hash {
	var e [8]byte
	binary.BigEndian.PutUint64(e[:], epoch)
	return crypto.Keccak256Hash([]byte("l1/epoch/seed"), e[:], random[:])
}

// EpochManager guarda la información de las épocas conocidas. Es seguro
// para uso concurrente.
type EpochManager struct {
	params  EpochParams
	staking StakingParams
	keep    int

	mu     sync.RWMutex
	epochs map[uint64]*EpochInfo
	// OnNewEpoch, si no es nil, se invoca al registrar una época nueva.
	OnNewEpoch func(*EpochInfo)
}

// NewEpochManager crea el gestor con el conjunto del génesis (épocas 0 y 1).
// keep es cuántas épocas pasadas se conservan (mínimo 4).
func NewEpochManager(params EpochParams, staking StakingParams, genesis *types.Header, genesisSet *ValidatorSet, keep int) *EpochManager {
	if keep < 4 {
		keep = 4
	}
	m := &EpochManager{params: params, staking: staking, keep: keep, epochs: map[uint64]*EpochInfo{}}
	for e := uint64(0); e < 2; e++ {
		m.epochs[e] = &EpochInfo{Epoch: e, StartBlock: params.FirstBlock(e), Validators: genesisSet, Seed: EpochSeed(e, genesis.Random)}
	}
	return m
}

// Params devuelve los parámetros de época.
func (m *EpochManager) Params() EpochParams { return m.params }

// Get devuelve la información de una época.
func (m *EpochManager) Get(epoch uint64) (*EpochInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	info, ok := m.epochs[epoch]
	if !ok {
		return nil, fmt.Errorf("%w: %d", ErrUnknownEpoch, epoch)
	}
	return info, nil
}

// ValidatorSet implementa ValidatorSetProvider.
func (m *EpochManager) ValidatorSet(epoch uint64) (*ValidatorSet, error) {
	info, err := m.Get(epoch)
	if err != nil {
		return nil, err
	}
	return info.Validators, nil
}

// ForBlock devuelve la época de una altura.
func (m *EpochManager) ForBlock(number uint64) (*EpochInfo, error) {
	return m.Get(m.params.EpochOf(number))
}

// Set registra (o sustituye) una época; lo usan la restauración desde disco
// y las pruebas.
func (m *EpochManager) Set(info *EpochInfo) {
	m.mu.Lock()
	m.epochs[info.Epoch] = info
	m.pruneLocked(info.Epoch)
	cb := m.OnNewEpoch
	m.mu.Unlock()
	if cb != nil {
		cb(info)
	}
}

// OnBlockFinalized debe llamarse con cada bloque FINAL (en orden) y el
// estado tras ejecutarlo. Si el bloque cierra una época e, deriva y
// registra la época e+2. Devuelve la nueva época (o nil).
func (m *EpochManager) OnBlockFinalized(header *types.Header, st execution.StakingReader) (*EpochInfo, error) {
	if !m.params.IsLastBlock(header.Number) {
		return nil, nil
	}
	target := m.params.EpochOf(header.Number) + 2
	if _, err := m.Get(target); err == nil {
		return nil, nil // ya registrada (re-procesado idempotente)
	}
	set, err := ValidatorSetFromState(st, m.staking)
	if err != nil {
		// Sin validadores elegibles la cadena se detendría: se conserva el
		// conjunto vigente como red de seguridad.
		prev, perr := m.Get(target - 1)
		if perr != nil {
			return nil, err
		}
		set = prev.Validators
	}
	info := &EpochInfo{Epoch: target, StartBlock: m.params.FirstBlock(target), Validators: set, Seed: EpochSeed(target, header.Random)}
	m.Set(info)
	return info, nil
}

// Known devuelve las épocas registradas en orden ascendente.
func (m *EpochManager) Known() []uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]uint64, 0, len(m.epochs))
	for e := range m.epochs {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// pruneLocked descarta épocas más antiguas que newest-keep.
func (m *EpochManager) pruneLocked(newest uint64) {
	if newest < uint64(m.keep) {
		return
	}
	limit := newest - uint64(m.keep)
	for e := range m.epochs {
		if e < limit {
			delete(m.epochs, e)
		}
	}
}
