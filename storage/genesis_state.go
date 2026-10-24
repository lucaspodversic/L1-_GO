package storage

// Construcción y persistencia del estado génesis.
//
// El génesis define el bloque 0: cuentas prefinanciadas, contratos de
// sistema y validadores iniciales. Todos los nodos deben obtener EXACTAMENTE
// la misma raíz de estado, por lo que la asignación se aplica en orden
// determinista (direcciones ordenadas), aunque el trie no dependa del orden.

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/l1/l1/types"
)

// ErrGenesisMismatch indica que la base ya contiene un génesis distinto.
var ErrGenesisMismatch = errors.New("storage: la base de datos contiene un génesis distinto")

// applyGenesisAlloc escribe la asignación inicial en un StateDB.
func applyGenesisAlloc(g *types.Genesis, st *StateDB) {
	for _, addr := range g.SortedAllocAddresses() {
		acc := g.Alloc[addr]
		st.SetBalance(addr, acc.Balance)
		st.SetNonce(addr, acc.Nonce)
		if len(acc.Code) > 0 {
			st.SetCode(addr, acc.Code)
		}
		for k, v := range acc.Storage {
			st.SetState(addr, k, v)
		}
	}
}

// GenesisStateRoot calcula la raíz de estado del génesis en memoria, sin
// tocar ninguna base de datos (útil para validar ficheros de génesis).
func GenesisStateRoot(g *types.Genesis) (types.Hash, error) {
	st, err := New(types.EmptyRootHash, NewMemoryStateDatabase())
	if err != nil {
		return types.Hash{}, err
	}
	applyGenesisAlloc(g, st)
	root := st.IntermediateRoot(false) // en génesis no se borran cuentas vacías
	return root, st.Error()
}

// CommitGenesis escribe el estado y el bloque génesis. Si la base ya tiene
// un bloque 0 canónico, comprueba que coincide (idempotente) y devuelve el
// existente; si difiere devuelve ErrGenesisMismatch.
func CommitGenesis(g *types.Genesis, sdb *StateDatabase, blocks *BlockStore) (*types.Block, error) {
	if err := g.Validate(); err != nil {
		return nil, fmt.Errorf("génesis inválido: %w", err)
	}
	expected, err := GenesisStateRoot(g)
	if err != nil {
		return nil, err
	}
	block := g.ToBlock(expected)
	if stored := ReadCanonicalHash(blocks.DB(), 0); !stored.IsZero() {
		if stored != block.Hash() {
			return nil, fmt.Errorf("%w: almacenado %s, configurado %s", ErrGenesisMismatch, stored, block.Hash())
		}
		return blocks.BlockByHash(stored)
	}
	// Estado real, confirmado y volcado a disco.
	st, err := New(types.EmptyRootHash, sdb)
	if err != nil {
		return nil, err
	}
	applyGenesisAlloc(g, st)
	root, err := st.Commit(false, true)
	if err != nil {
		return nil, err
	}
	if root != expected {
		return nil, fmt.Errorf("storage: raíz de génesis inconsistente (%s != %s)", root, expected)
	}
	if err := blocks.WriteBlock(block, types.Receipts{}, true); err != nil {
		return nil, err
	}
	if err := blocks.SetFinalized(block.Hash()); err != nil {
		return nil, err
	}
	spec, err := json.Marshal(g)
	if err != nil {
		return nil, err
	}
	if err := blocks.DB().Put(genesisSpecKey, spec); err != nil {
		return nil, err
	}
	return block, nil
}

// ReadGenesisSpec devuelve el génesis guardado (nil si no hay).
func ReadGenesisSpec(r KeyValueReader) (*types.Genesis, error) {
	data, err := r.Get(genesisSpecKey)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return types.ParseGenesis(data)
}
