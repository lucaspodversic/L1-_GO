package execution

// Este archivo implementa los contratos de sistema: contratos con dirección
// reservada cuya lógica está escrita en Go en lugar de bytecode. Se invocan
// con CALL/STATICCALL como cualquier contrato (ABI de Solidity), pero su
// estado vive en el almacenamiento de la cuenta del contrato, de modo que
// queda comprometido en la raíz de estado y se revierte con los snapshots
// igual que el de un contrato normal.
//
// El único contrato de sistema por defecto es el de STAKING (0x…1000):
//
//	register(bytes blsPubKey, bytes pop)  payable  alta de validador
//	deposit()                             payable  aumentar el stake propio
//	unbond(uint256 amount)                         iniciar retirada (desvinculación)
//	withdraw()                                     cobrar lo desvinculado y madurado
//	unjail()                                       salir de la cárcel cumplido el plazo
//	getValidator(address)                 view     (stake, status, blsKey, unbonding, releaseEpoch)
//	validatorCount() / validatorAt(uint256) / totalStake()   view
//
// El paquete consensus lee y modifica (recompensas, slashing, cárcel) este
// mismo estado mediante las funciones Read*/Write*/Slash* exportadas aquí,
// lo que evita un ciclo de importación consensus <-> execution.

import (
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/l1/l1/crypto"
	"github.com/l1/l1/types"
)

// StakingContractAddress es la dirección reservada del contrato de staking.
var StakingContractAddress = types.Address{18: 0x10}

// SystemContract es un contrato nativo.
type SystemContract interface {
	// RequiredGas devuelve el gas fijo de la llamada según el selector.
	RequiredGas(input []byte) uint64
	// Run ejecuta la llamada. Para revertir devuelve datos de
	// Error(string) junto con ErrExecutionReverted.
	Run(ctx *SystemCallContext, input []byte) ([]byte, error)
}

// SystemCallContext es el entorno de una llamada a un contrato de sistema.
type SystemCallContext struct {
	EVM      *EVM
	Self     types.Address
	Caller   types.Address
	Value    *Word
	ReadOnly bool
}

// DefaultSystemContracts devuelve el conjunto estándar.
func DefaultSystemContracts() map[types.Address]SystemContract {
	return map[types.Address]SystemContract{
		StakingContractAddress: NewStakingContract(DefaultStakingConfig()),
	}
}

// runSystemContract cobra el gas y ejecuta el contrato nativo.
func runSystemContract(evm *EVM, sys SystemContract, caller types.Address, input []byte, gas uint64, value *Word, readOnly bool) ([]byte, uint64, error) {
	cost := sys.RequiredGas(input)
	if gas < cost {
		return nil, 0, ErrOutOfGas
	}
	gas -= cost
	var self types.Address
	for a, s := range evm.system {
		if s == sys {
			self = a
			break
		}
	}
	ctx := &SystemCallContext{EVM: evm, Self: self, Caller: caller, Value: value, ReadOnly: readOnly}
	ret, err := sys.Run(ctx, input)
	return ret, gas, err
}

// revertWith construye un revert con motivo legible.
func revertWith(reason string) ([]byte, error) {
	return EncodeRevertReason(reason), ErrExecutionReverted
}

// ---------------------------------------------------------------------------
// Estado de staking
// ---------------------------------------------------------------------------

// Estados de un validador.
const (
	ValidatorNone   uint8 = 0 // no registrado
	ValidatorActive uint8 = 1 // elegible para el conjunto de validadores
	ValidatorJailed uint8 = 2 // encarcelado (no elegible hasta JailedUntil)
	ValidatorExited uint8 = 3 // retiró todo su stake
)

// ValidatorRecord es la ficha de un validador en el contrato de staking.
type ValidatorRecord struct {
	Address         types.Address
	BLSKey          []byte // 48 bytes comprimidos (G1)
	Stake           types.Amount
	Status          uint8
	Unbonding       types.Amount // importe en desvinculación
	ReleaseEpoch    uint64       // época desde la que se puede retirar
	Slashed         types.Amount // total penalizado históricamente
	JailedUntil     uint64       // época hasta la que está encarcelado
	RegisteredEpoch uint64
}

// StakingReader es lo mínimo para leer el estado de staking.
type StakingReader interface {
	GetState(types.Address, types.Hash) types.Hash
}

// StakingWriter permite además modificarlo.
type StakingWriter interface {
	StakingReader
	SetState(types.Address, types.Hash, types.Hash)
	GetNonce(types.Address) uint64
	SetNonce(types.Address, uint64)
	GetBalance(types.Address) types.Amount
	AddBalance(types.Address, types.Amount)
	SubBalance(types.Address, types.Amount) error
}

// Campos de la ficha (desplazamiento sobre la ranura base del validador).
const (
	fieldStake byte = iota
	fieldStatus
	fieldUnbonding
	fieldRelease
	fieldKey0
	fieldKey1
	fieldSlashed
	fieldJailed
	fieldRegistered
	fieldIndex // índice + 1 en la lista (0 = no está)
)

var (
	slotCount = types.Keccak256Hash([]byte("l1.staking.count"))
	slotTotal = types.Keccak256Hash([]byte("l1.staking.total"))
)

// validatorSlot = keccak("l1.staking.val" || addr || campo).
func validatorSlot(addr types.Address, field byte) types.Hash {
	return types.Keccak256Hash([]byte("l1.staking.val"), addr[:], []byte{field})
}

// listSlot = keccak("l1.staking.list" || i).
func listSlot(i uint64) types.Hash {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], i)
	return types.Keccak256Hash([]byte("l1.staking.list"), b[:])
}

func hashToAmount(h types.Hash) types.Amount {
	return types.MustAmountFromBig(new(big.Int).SetBytes(h[:]))
}

func amountToHash(a types.Amount) types.Hash { return types.Hash(a.Bytes32()) }

func hashToUint(h types.Hash) uint64 { return binary.BigEndian.Uint64(h[24:]) }

func uintToHash(v uint64) (h types.Hash) {
	binary.BigEndian.PutUint64(h[24:], v)
	return h
}

// ReadValidator lee la ficha de addr.
func ReadValidator(db StakingReader, addr types.Address) (*ValidatorRecord, bool) {
	c := StakingContractAddress
	status := uint8(hashToUint(db.GetState(c, validatorSlot(addr, fieldStatus))))
	if status == ValidatorNone {
		return nil, false
	}
	k0 := db.GetState(c, validatorSlot(addr, fieldKey0))
	k1 := db.GetState(c, validatorSlot(addr, fieldKey1))
	key := make([]byte, 48)
	copy(key, k0[:])
	copy(key[32:], k1[:16])
	return &ValidatorRecord{
		Address:         addr,
		BLSKey:          key,
		Stake:           hashToAmount(db.GetState(c, validatorSlot(addr, fieldStake))),
		Status:          status,
		Unbonding:       hashToAmount(db.GetState(c, validatorSlot(addr, fieldUnbonding))),
		ReleaseEpoch:    hashToUint(db.GetState(c, validatorSlot(addr, fieldRelease))),
		Slashed:         hashToAmount(db.GetState(c, validatorSlot(addr, fieldSlashed))),
		JailedUntil:     hashToUint(db.GetState(c, validatorSlot(addr, fieldJailed))),
		RegisteredEpoch: hashToUint(db.GetState(c, validatorSlot(addr, fieldRegistered))),
	}, true
}

// ensureNonEmpty da nonce 1 a la cuenta del contrato para que EIP-161 no
// la considere vacía y la borre junto con su almacenamiento.
func ensureNonEmpty(db StakingWriter) {
	if db.GetNonce(StakingContractAddress) == 0 {
		db.SetNonce(StakingContractAddress, 1)
	}
}

// WriteValidator guarda la ficha y la añade a la lista si es nueva.
func WriteValidator(db StakingWriter, r *ValidatorRecord) {
	ensureNonEmpty(db)
	c, a := StakingContractAddress, r.Address
	if hashToUint(db.GetState(c, validatorSlot(a, fieldIndex))) == 0 {
		n := hashToUint(db.GetState(c, slotCount))
		db.SetState(c, listSlot(n), types.BytesToHash(a[:]))
		db.SetState(c, slotCount, uintToHash(n+1))
		db.SetState(c, validatorSlot(a, fieldIndex), uintToHash(n+1))
	}
	var k0, k1 types.Hash
	copy(k0[:], r.BLSKey)
	if len(r.BLSKey) > 32 {
		copy(k1[:], r.BLSKey[32:])
	}
	db.SetState(c, validatorSlot(a, fieldKey0), k0)
	db.SetState(c, validatorSlot(a, fieldKey1), k1)
	db.SetState(c, validatorSlot(a, fieldStake), amountToHash(r.Stake))
	db.SetState(c, validatorSlot(a, fieldStatus), uintToHash(uint64(r.Status)))
	db.SetState(c, validatorSlot(a, fieldUnbonding), amountToHash(r.Unbonding))
	db.SetState(c, validatorSlot(a, fieldRelease), uintToHash(r.ReleaseEpoch))
	db.SetState(c, validatorSlot(a, fieldSlashed), amountToHash(r.Slashed))
	db.SetState(c, validatorSlot(a, fieldJailed), uintToHash(r.JailedUntil))
	db.SetState(c, validatorSlot(a, fieldRegistered), uintToHash(r.RegisteredEpoch))
}

// ValidatorCount devuelve cuántos validadores se han registrado nunca.
func ValidatorCount(db StakingReader) uint64 {
	return hashToUint(db.GetState(StakingContractAddress, slotCount))
}

// ValidatorAt devuelve la dirección del i-ésimo registrado.
func ValidatorAt(db StakingReader, i uint64) types.Address {
	h := db.GetState(StakingContractAddress, listSlot(i))
	return types.BytesToAddress(h[12:])
}

// ReadAllValidators devuelve todas las fichas en orden de registro.
func ReadAllValidators(db StakingReader) []*ValidatorRecord {
	n := ValidatorCount(db)
	out := make([]*ValidatorRecord, 0, n)
	for i := uint64(0); i < n; i++ {
		if r, ok := ReadValidator(db, ValidatorAt(db, i)); ok {
			out = append(out, r)
		}
	}
	return out
}

// TotalStake devuelve el stake vinculado total (sin lo desvinculado).
func TotalStake(db StakingReader) types.Amount {
	return hashToAmount(db.GetState(StakingContractAddress, slotTotal))
}

// SetTotalStake fija el stake total agregado (lo usa la construcción del
// génesis al instalar validadores directamente en el estado).
func SetTotalStake(db StakingWriter, a types.Amount) { setTotalStake(db, a) }

func setTotalStake(db StakingWriter, a types.Amount) {
	db.SetState(StakingContractAddress, slotTotal, amountToHash(a))
}

// SlashValidator penaliza amount del validador: se descuenta primero del
// stake vinculado y después del importe en desvinculación (para que no se
// pueda escapar de una penalización iniciando la retirada). Los fondos se
// queman (salen del saldo del contrato). Devuelve lo realmente penalizado.
func SlashValidator(db StakingWriter, addr types.Address, amount types.Amount) types.Amount {
	r, ok := ReadValidator(db, addr)
	if !ok || amount.IsZero() {
		return types.Amount{}
	}
	fromStake := amount.Min(r.Stake)
	r.Stake = r.Stake.Sub(fromStake)
	setTotalStake(db, TotalStake(db).Sub(fromStake.Min(TotalStake(db))))
	rest := amount.Sub(fromStake)
	fromUnbond := rest.Min(r.Unbonding)
	r.Unbonding = r.Unbonding.Sub(fromUnbond)
	slashed := fromStake.Add(fromUnbond)
	r.Slashed = r.Slashed.Add(slashed)
	WriteValidator(db, r)
	if !slashed.IsZero() {
		// El contrato siempre custodia stake + desvinculado; no puede fallar
		// salvo corrupción del estado, en cuyo caso no quemamos nada.
		_ = db.SubBalance(StakingContractAddress, slashed)
	}
	return slashed
}

// JailValidator encarcela al validador hasta untilEpoch (inclusive).
func JailValidator(db StakingWriter, addr types.Address, untilEpoch uint64) bool {
	r, ok := ReadValidator(db, addr)
	if !ok || r.Status == ValidatorExited {
		return false
	}
	r.Status = ValidatorJailed
	if untilEpoch > r.JailedUntil {
		r.JailedUntil = untilEpoch
	}
	WriteValidator(db, r)
	return true
}

// ---------------------------------------------------------------------------
// Contrato de staking
// ---------------------------------------------------------------------------

// StakingConfig parametriza el contrato.
type StakingConfig struct {
	// MinStake es el stake mínimo para estar activo.
	MinStake types.Amount
	// UnbondingEpochs es el retardo entre unbond y withdraw.
	UnbondingEpochs uint64
}

// DefaultStakingConfig: 1 ether de mínimo y 2 épocas de desvinculación.
func DefaultStakingConfig() StakingConfig {
	return StakingConfig{MinStake: types.EtherAmount(1), UnbondingEpochs: 2}
}

// StakingContract implementa SystemContract.
type StakingContract struct {
	cfg StakingConfig
}

// NewStakingContract crea el contrato con su configuración.
func NewStakingContract(cfg StakingConfig) *StakingContract { return &StakingContract{cfg: cfg} }

// Selectores de las funciones.
var (
	selRegister       = Selector("register(bytes,bytes)")
	selDeposit        = Selector("deposit()")
	selUnbond         = Selector("unbond(uint256)")
	selWithdraw       = Selector("withdraw()")
	selUnjail         = Selector("unjail()")
	selGetValidator   = Selector("getValidator(address)")
	selValidatorCount = Selector("validatorCount()")
	selValidatorAt    = Selector("validatorAt(uint256)")
	selTotalStake     = Selector("totalStake()")
)

// Temas de los eventos.
var (
	EventValidatorRegistered = EventSignature("ValidatorRegistered(address,bytes)")
	EventDeposited           = EventSignature("Deposited(address,uint256)")
	EventUnbonded            = EventSignature("Unbonded(address,uint256,uint256)")
	EventWithdrawn           = EventSignature("Withdrawn(address,uint256)")
	EventUnjailed            = EventSignature("Unjailed(address)")
)

// Costes de gas de las funciones.
const (
	stakingGasRegister = 100_000 // incluye la verificación BLS de la PoP
	stakingGasWrite    = 30_000
	stakingGasView     = 2_600
)

// RequiredGas devuelve el coste según el selector.
func (c *StakingContract) RequiredGas(input []byte) uint64 {
	if len(input) < 4 {
		return stakingGasView
	}
	var sel [4]byte
	copy(sel[:], input)
	switch sel {
	case selRegister:
		return stakingGasRegister
	case selDeposit, selUnbond, selWithdraw, selUnjail:
		return stakingGasWrite
	}
	return stakingGasView
}

// topicAddr convierte una dirección en tema de log.
func topicAddr(a types.Address) types.Hash { return types.BytesToHash(a[:]) }

// Run despacha según el selector.
func (c *StakingContract) Run(ctx *SystemCallContext, input []byte) ([]byte, error) {
	if len(input) < 4 {
		if ctx.Value != nil && !ctx.Value.IsZero() {
			return revertWith("staking: use deposit() para enviar fondos")
		}
		return nil, nil
	}
	var sel [4]byte
	copy(sel[:], input)
	args := input[4:]
	db := ctx.EVM.StateDB
	payable := sel == selRegister || sel == selDeposit
	if !payable && ctx.Value != nil && !ctx.Value.IsZero() {
		return revertWith("staking: función no payable")
	}
	mutating := payable || sel == selUnbond || sel == selWithdraw || sel == selUnjail
	if mutating && ctx.ReadOnly {
		return nil, ErrWriteProtection
	}
	epoch := ctx.EVM.Context.Epoch

	switch sel {
	case selRegister:
		vals, err := DecodeABI([]string{"bytes", "bytes"}, args)
		if err != nil {
			return revertWith("staking: argumentos inválidos")
		}
		keyB, popB := vals[0].([]byte), vals[1].([]byte)
		if _, exists := ReadValidator(db, ctx.Caller); exists {
			return revertWith("staking: validador ya registrado")
		}
		pk, err := crypto.BLSPublicKeyFromBytes(keyB)
		if err != nil {
			return revertWith("staking: clave BLS inválida")
		}
		pop, err := crypto.BLSSignatureFromBytes(popB)
		if err != nil || !pk.VerifyPossession(pop) {
			return revertWith("staking: prueba de posesión inválida")
		}
		stake := ctx.Value.ToAmount()
		if stake.Lt(c.cfg.MinStake) {
			return revertWith("staking: stake inferior al mínimo")
		}
		WriteValidator(db, &ValidatorRecord{
			Address: ctx.Caller, BLSKey: pk.Bytes(), Stake: stake,
			Status: ValidatorActive, RegisteredEpoch: epoch,
		})
		setTotalStake(db, TotalStake(db).Add(stake))
		data, _ := EncodeABI([]string{"bytes"}, []any{pk.Bytes()})
		EmitLog(ctx.EVM, ctx.Self, []types.Hash{EventValidatorRegistered, topicAddr(ctx.Caller)}, data)
		return nil, nil

	case selDeposit:
		r, ok := ReadValidator(db, ctx.Caller)
		if !ok || r.Status == ValidatorExited {
			return revertWith("staking: validador no registrado o retirado")
		}
		amt := ctx.Value.ToAmount()
		if amt.IsZero() {
			return revertWith("staking: depósito nulo")
		}
		r.Stake = r.Stake.Add(amt)
		WriteValidator(db, r)
		setTotalStake(db, TotalStake(db).Add(amt))
		EmitLog(ctx.EVM, ctx.Self, []types.Hash{EventDeposited, topicAddr(ctx.Caller)}, abiUint256(amt))
		return nil, nil

	case selUnbond:
		vals, err := DecodeABI([]string{"uint256"}, args)
		if err != nil {
			return revertWith("staking: argumentos inválidos")
		}
		amt := types.MustAmountFromBig(vals[0].(*big.Int))
		r, ok := ReadValidator(db, ctx.Caller)
		if !ok {
			return revertWith("staking: validador no registrado")
		}
		if amt.IsZero() || amt.Gt(r.Stake) {
			return revertWith("staking: importe de desvinculación inválido")
		}
		remaining := r.Stake.Sub(amt)
		if !remaining.IsZero() && remaining.Lt(c.cfg.MinStake) {
			return revertWith("staking: el stake restante quedaría bajo el mínimo")
		}
		r.Stake = remaining
		r.Unbonding = r.Unbonding.Add(amt)
		r.ReleaseEpoch = epoch + c.cfg.UnbondingEpochs
		if remaining.IsZero() {
			r.Status = ValidatorExited
		}
		WriteValidator(db, r)
		setTotalStake(db, TotalStake(db).Sub(amt))
		data, _ := EncodeABI([]string{"uint256", "uint256"}, []any{amt, r.ReleaseEpoch})
		EmitLog(ctx.EVM, ctx.Self, []types.Hash{EventUnbonded, topicAddr(ctx.Caller)}, data)
		return nil, nil

	case selWithdraw:
		r, ok := ReadValidator(db, ctx.Caller)
		if !ok || r.Unbonding.IsZero() {
			return revertWith("staking: nada que retirar")
		}
		if epoch < r.ReleaseEpoch {
			return revertWith("staking: desvinculación aún no madurada")
		}
		amt := r.Unbonding
		r.Unbonding = types.Amount{}
		WriteValidator(db, r)
		if err := TransferAmount(db, ctx.Self, ctx.Caller, amt); err != nil {
			return revertWith("staking: saldo del contrato insuficiente")
		}
		EmitLog(ctx.EVM, ctx.Self, []types.Hash{EventWithdrawn, topicAddr(ctx.Caller)}, abiUint256(amt))
		return nil, nil

	case selUnjail:
		r, ok := ReadValidator(db, ctx.Caller)
		if !ok || r.Status != ValidatorJailed {
			return revertWith("staking: el validador no está encarcelado")
		}
		if epoch <= r.JailedUntil {
			return revertWith("staking: condena no cumplida")
		}
		if r.Stake.Lt(c.cfg.MinStake) {
			return revertWith("staking: stake bajo el mínimo; deposite antes")
		}
		r.Status = ValidatorActive
		WriteValidator(db, r)
		EmitLog(ctx.EVM, ctx.Self, []types.Hash{EventUnjailed, topicAddr(ctx.Caller)}, nil)
		return nil, nil

	case selGetValidator:
		vals, err := DecodeABI([]string{"address"}, args)
		if err != nil {
			return revertWith("staking: argumentos inválidos")
		}
		r, ok := ReadValidator(db, vals[0].(types.Address))
		if !ok {
			r = &ValidatorRecord{BLSKey: []byte{}}
		}
		return EncodeABI([]string{"uint256", "uint8", "bytes", "uint256", "uint256"},
			[]any{r.Stake, r.Status, r.BLSKey, r.Unbonding, r.ReleaseEpoch})

	case selValidatorCount:
		return abiUint(ValidatorCount(db)), nil

	case selValidatorAt:
		vals, err := DecodeABI([]string{"uint256"}, args)
		if err != nil {
			return revertWith("staking: argumentos inválidos")
		}
		i := vals[0].(*big.Int)
		if !i.IsUint64() || i.Uint64() >= ValidatorCount(db) {
			return revertWith("staking: índice fuera de rango")
		}
		a := ValidatorAt(db, i.Uint64())
		return EncodeABI([]string{"address"}, []any{a})

	case selTotalStake:
		return abiUint256(TotalStake(db)), nil
	}
	return revertWith("staking: función desconocida")
}

// abiUint256 codifica un Amount en una palabra.
func abiUint256(a types.Amount) []byte {
	b := a.Bytes32()
	return b[:]
}

// errSystemNotFound se usa cuando falta un contrato de sistema esperado.
var errSystemNotFound = errors.New("contrato de sistema no configurado")

// CallSystem ejecuta una llamada desde la dirección "sistema" (cero) a un
// contrato de sistema fuera de una transacción (p.ej. en el procesador de
// bloques). No cobra gas al llamador.
func CallSystem(evm *EVM, addr types.Address, input []byte) ([]byte, error) {
	sys, ok := evm.systemContract(addr)
	if !ok {
		return nil, errSystemNotFound
	}
	ctx := &SystemCallContext{EVM: evm, Self: addr, Caller: types.Address{}, Value: new(Word)}
	return sys.Run(ctx, input)
}
