package consensus

// ConsensusService es el motor BFT completo: combina pacemaker, árbol de
// bloques, recolectores de votos/timeouts, reglas de seguridad y el
// constructor de bloques (execution.ExecutorService) para producir,
// votar y finalizar bloques. Implementa Engine.

import (
	"fmt"
	"sync"
	"time"

	"github.com/l1/l1/crypto"
	"github.com/l1/l1/execution"
	"github.com/l1/l1/mempool"
	"github.com/l1/l1/storage"
	"github.com/l1/l1/types"
)

// BlockCommitter persiste un bloque recién construido o recibido.
type BlockCommitter interface {
	WriteBlock(b *types.Block, receipts types.Receipts, canonical bool) error
	SetFinalized(hash types.Hash) error
	SetCanonical(hash types.Hash) error
}

// TxSource suministra transacciones al constructor de bloques.
type TxSource interface {
	Iterator() execution.TxIterator
	NotifyNewHead(h *types.Header)
}

// ServiceConfig parametriza el servicio de consenso.
type ServiceConfig struct {
	ChainID   types.ChainID
	Key       *ValidatorKey // nil = nodo no validador (sólo observa)
	Timeouts  TimeoutConfig
	BlockTime time.Duration // retardo mínimo entre propuestas propias
	GasLimit  uint64
}

// Service es el motor de consenso en ejecución.
type Service struct {
	mu sync.Mutex

	cfg      ServiceConfig
	epochs   *EpochManager
	elector  LeaderElector
	headers  *HeaderValidator
	blocks   *BlockValidator
	tree     *BlockTree
	finality *FinalityTracker
	pace     *Pacemaker
	safety   *SafetyRules
	votes    *VoteCollector
	timeouts *TimeoutCollector
	equiv    *EquivocationTracker
	wal      *ConsensusWAL

	exec   *execution.ExecutorService
	store  BlockCommitter
	txs    TxSource
	net    Broadcaster
	reward *RewardFinalizer

	genesis *types.Block
	running bool
	stopCh  chan struct{}
	wg      sync.WaitGroup

	// OnCommit se invoca (fuera del cerrojo) tras finalizar bloques.
	OnCommit CommitHandler
}

// NewService construye el motor. genesis debe ser el bloque 0 ya escrito.
func NewService(
	cfg ServiceConfig,
	genesis *types.Block,
	epochs *EpochManager,
	exec *execution.ExecutorService,
	store BlockCommitter,
	txs TxSource,
	net Broadcaster,
	wal *ConsensusWAL,
	reward *RewardFinalizer,
) (*Service, error) {
	if cfg.Timeouts.Base == 0 {
		cfg.Timeouts = DefaultTimeoutConfig()
	}
	if cfg.BlockTime == 0 {
		cfg.BlockTime = 200 * time.Millisecond
	}
	if cfg.GasLimit == 0 {
		cfg.GasLimit = types.DefaultGasLimit
	}
	gqc := GenesisQC(genesis.HeaderRef())
	hv := NewHeaderValidator(cfg.ChainID, epochs.Params(), execution.DefaultFeeConfig())
	bv := NewBlockValidator(hv, epochs, WeightedElector{}, genesis.Hash())
	tree := NewBlockTree(genesis, gqc)
	round := NewRoundState(0, gqc)
	safety := NewSafetyRules(round, wal)
	if err := safety.RestoreFromWAL(); err != nil {
		return nil, err
	}
	s := &Service{
		cfg: cfg, epochs: epochs, elector: WeightedElector{}, headers: hv, blocks: bv,
		tree: tree, pace: NewPacemaker(cfg.Timeouts, RealClock(), gqc),
		safety: safety, equiv: NewEquivocationTracker(cfg.ChainID), wal: wal,
		exec: exec, store: store, txs: txs, net: net, reward: reward, genesis: genesis,
		stopCh: make(chan struct{}),
	}
	s.finality = NewFinalityTracker(tree, s.onCommit)
	info, err := epochs.Get(0)
	if err != nil {
		return nil, err
	}
	s.votes = NewVoteCollector(cfg.ChainID, 0, info.Validators)
	s.timeouts = NewTimeoutCollector(cfg.ChainID, 0, info.Validators, epochs)
	s.pace.OnNewView = s.onNewView
	s.pace.OnTimeout = s.onTimeout
	return s, nil
}

// Finalizer implementa Engine.
func (s *Service) Finalizer() execution.Finalizer { return s.reward }

// Author implementa Engine.
func (s *Service) Author(header *types.Header) (types.Address, error) {
	return header.Proposer, nil
}

// VerifyHeader implementa Engine.
func (s *Service) VerifyHeader(chain ChainReader, header *types.Header) error {
	parent, err := chain.HeaderByHash(header.ParentHash)
	if err != nil || parent == nil {
		return ErrUnknownParent
	}
	return s.headers.VerifyHeader(header, parent)
}

// VerifyBlock implementa Engine.
func (s *Service) VerifyBlock(chain ChainReader, block *types.Block) error {
	parent, err := chain.HeaderByHash(block.ParentHash())
	if err != nil || parent == nil {
		return ErrUnknownParent
	}
	_, err = s.blocks.ValidateBlock(block, parent)
	return err
}

// Prepare rellena campos de consenso de una cabecera a proponer.
func (s *Service) Prepare(chain ChainReader, header *types.Header) error {
	info, err := s.epochs.ForBlock(header.Number)
	if err != nil {
		return err
	}
	header.Epoch = info.Epoch
	header.ValidatorsHash = info.Validators.Hash()
	return nil
}

// Start arranca el pacemaker.
func (s *Service) Start() error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = true
	s.mu.Unlock()
	s.pace.Start()
	return nil
}

// Stop detiene el motor.
func (s *Service) Stop() error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = false
	close(s.stopCh)
	s.mu.Unlock()
	s.pace.Stop()
	s.wg.Wait()
	return nil
}

// HandleMessage procesa un mensaje de consenso de la red.
func (s *Service) HandleMessage(_ types.Address, msg []byte) error {
	t, payload, err := DecodeMessage(msg)
	if err != nil {
		return err
	}
	switch t {
	case MsgProposal:
		return s.handleProposal(payload.(*Proposal))
	case MsgVote:
		return s.handleVote(payload.(*Vote))
	case MsgTimeout:
		return s.handleTimeoutMsg(payload.(*TimeoutMsg))
	case MsgTimeoutCert:
		return s.handleTC(payload.(*TimeoutCert))
	case MsgQuorumCert:
		return s.handleQC(payload.(*QuorumCert))
	case MsgEvidence:
		return s.handleEvidence(payload.(*DoubleVoteEvidence))
	default:
		return nil
	}
}

// -------------------------------------------------------------------------
// Bucle de protocolo
// -------------------------------------------------------------------------

func (s *Service) onNewView(view uint64, reason ViewChangeReason) {
	// Siempre asíncrono: ProcessQC/ProcessTC pueden invocarse con s.mu tomado
	// (applyQCLocked/applyTCLocked); reentrar en onNewView con Lock provocaría deadlock.
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.handleNewView(view, reason)
	}()
}

func (s *Service) handleNewView(view uint64, reason ViewChangeReason) {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	epoch := s.currentEpochLocked()
	s.safety.Round().EnterView(epoch, view)
	info, err := s.epochs.Get(epoch)
	leader := err == nil && s.cfg.Key != nil && IsLeader(s.elector, info, view, s.cfg.Key.Address)
	blockTime := s.cfg.BlockTime
	s.mu.Unlock()
	_ = reason
	if !leader {
		return
	}
	// Esperar el intervalo de bloque fuera del cerrojo.
	time.Sleep(blockTime)
	s.propose(view)
}

func (s *Service) onTimeout(view uint64, attempt int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running || s.cfg.Key == nil {
		return
	}
	if err := s.safety.CommitTimeout(view); err != nil {
		return
	}
	epoch := s.currentEpochLocked()
	highQC := s.safety.Round().HighQC()
	if highQC == nil {
		highQC = s.pace.HighQC()
	}
	tm, err := NewTimeoutMsg(s.cfg.Key, s.cfg.ChainID, epoch, view, highQC)
	if err != nil {
		return
	}
	s.broadcastLocked(tm)
	res, err := s.timeouts.Add(tm)
	if err == nil && res.TC != nil {
		s.applyTCLocked(res.TC)
	}
	_ = attempt
}

func (s *Service) propose(view uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running || s.cfg.Key == nil {
		return
	}
	if s.pace.View() != view {
		return
	}
	parent := s.tree.PreferredHead()
	if parent == nil {
		return
	}
	highQC := s.tree.HighQC()
	if highQC == nil {
		return
	}
	epoch := s.currentEpochLocked()
	info, err := s.epochs.Get(epoch)
	if err != nil {
		return
	}
	beta, proof, err := s.cfg.Key.VRFProve(s.cfg.ChainID, epoch, view, parent.HeaderRef().Random)
	if err != nil {
		return
	}
	var it execution.TxIterator
	if s.txs != nil {
		it = s.txs.Iterator()
	}
	tc := s.pace.HighTC()
	// Si venimos de QC (camino feliz) no hace falta TC.
	if highQC.View+1 == view {
		tc = nil
	}
	res, err := s.exec.BuildBlock(parent.HeaderRef(), execution.BuildParams{
		Coinbase:       s.cfg.Key.Address,
		Timestamp:      uint64(time.Now().Unix()),
		Epoch:          epoch,
		View:           view,
		Random:         beta,
		GasLimit:       s.cfg.GasLimit,
		ValidatorsHash: info.Validators.Hash(),
		Justify:        highQC.EncodeRLP(),
	}, it)
	if err != nil {
		return
	}
	// Confirmar estado del bloque construido.
	if _, err := res.State.Commit(true, true); err != nil {
		return
	}
	p, err := NewProposal(s.cfg.Key, s.cfg.ChainID, res.Block, tc, proof)
	if err != nil {
		return
	}
	if err := s.tree.Insert(res.Block); err != nil {
		return
	}
	if s.store != nil {
		_ = s.store.WriteBlock(res.Block, res.Receipts, false)
	}
	s.broadcastLocked(p)
	// Auto-voto (necesario cuando N=1).
	s.voteForLocked(p, highQC)
}

func (s *Service) voteForLocked(p *Proposal, qc *QuorumCert) {
	if s.cfg.Key == nil {
		return
	}
	if err := s.safety.MayVote(p, qc); err != nil {
		return
	}
	if err := s.safety.CommitVote(p, qc); err != nil {
		return
	}
	h := p.Block.HeaderRef()
	v, err := NewVote(s.cfg.Key, s.cfg.ChainID, VoteData{
		Epoch: h.Epoch, View: h.View, BlockNumber: h.Number, BlockHash: p.Block.Hash(),
	})
	if err != nil {
		return
	}
	s.broadcastLocked(v)
	got, ev, err := s.votes.AddVote(v)
	if ev != nil {
		s.broadcastLocked(ev)
	}
	if err == nil && got != nil {
		s.applyQCLocked(got)
	}
}

func (s *Service) handleProposal(p *Proposal) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	parent, ok := s.tree.Get(p.Block.ParentHash())
	if !ok {
		return ErrUnknownParent
	}
	qc, err := s.blocks.ValidateProposal(p, parent.HeaderRef())
	if err != nil {
		return err
	}
	if err := s.equiv.ObserveProposal(p); err != nil {
		return err
	}
	if err := s.tree.Insert(p.Block); err != nil {
		return err
	}
	if s.store != nil {
		// Ejecutar para obtener recibos/estado.
		if s.exec != nil {
			pres, statedb, err := s.exec.ExecuteBlock(p.Block, parent.HeaderRef())
			if err == nil {
				_, _ = statedb.Commit(true, true)
				_ = s.store.WriteBlock(p.Block, pres.Receipts, false)
			}
		}
	}
	s.voteForLocked(p, qc)
	return nil
}

func (s *Service) handleVote(v *Vote) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ev, _ := s.equiv.ObserveVote(v); ev != nil {
		s.broadcastLocked(ev)
	}
	qc, ev, err := s.votes.AddVote(v)
	if ev != nil {
		s.broadcastLocked(ev)
	}
	if err != nil {
		return err
	}
	if qc != nil {
		s.applyQCLocked(qc)
	}
	return nil
}

func (s *Service) handleTimeoutMsg(t *TimeoutMsg) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.timeouts.Add(t)
	if err != nil {
		return err
	}
	if res.TC != nil {
		s.applyTCLocked(res.TC)
	}
	return nil
}

func (s *Service) handleTC(tc *TimeoutCert) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.applyTCLocked(tc)
	return nil
}

func (s *Service) handleQC(qc *QuorumCert) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.applyQCLocked(qc)
	return nil
}

func (s *Service) handleEvidence(ev *DoubleVoteEvidence) error {
	// La aplicación on-chain ocurre vía el contrato; aquí sólo retransmitimos.
	s.mu.Lock()
	defer s.mu.Unlock()
	s.broadcastLocked(ev)
	return nil
}

func (s *Service) applyQCLocked(qc *QuorumCert) {
	if qc == nil {
		return
	}
	s.safety.Round().UpdateHighQC(qc)
	s.pace.ProcessQC(qc)
	s.broadcastLocked(qc)
	committed, err := s.finality.ProcessQC(qc)
	if err != nil || len(committed) == 0 {
		return
	}
	// Persistencia canónica ya la hace onCommit.
	_ = committed
}

func (s *Service) applyTCLocked(tc *TimeoutCert) {
	if tc == nil {
		return
	}
	s.safety.Round().UpdateHighTC(tc)
	s.pace.ProcessTC(tc)
	s.broadcastLocked(tc)
}

func (s *Service) onCommit(blocks []*types.Block, qc *QuorumCert) {
	for _, b := range blocks {
		if s.store != nil {
			_ = s.store.SetCanonical(b.Hash())
			_ = s.store.SetFinalized(b.Hash())
		}
		if s.txs != nil {
			s.txs.NotifyNewHead(b.HeaderRef())
		}
		// Avance de época (si el bloque cierra una).
		if s.exec != nil {
			st, err := s.exec.StateAt(b.StateRoot())
			if err == nil {
				_, _ = s.epochs.OnBlockFinalized(b.HeaderRef(), st)
			}
		}
	}
	if s.OnCommit != nil {
		s.OnCommit(blocks, qc)
	}
}

func (s *Service) broadcastLocked(msg any) {
	if s.net == nil {
		return
	}
	b, err := EncodeMessage(msg)
	if err != nil {
		return
	}
	_ = s.net.Broadcast(b)
}

func (s *Service) currentEpochLocked() uint64 {
	head := s.tree.PreferredHead()
	if head == nil {
		return 0
	}
	info, err := s.epochs.ForBlock(head.Number() + 1)
	if err != nil {
		return head.HeaderRef().Epoch
	}
	return info.Epoch
}

// Tree expone el árbol de bloques (para sync/RPC).
func (s *Service) Tree() *BlockTree { return s.tree }

// Pacemaker expone el pacemaker.
func (s *Service) Pacemaker() *Pacemaker { return s.pace }

// Finalized expone el último bloque final.
func (s *Service) Finalized() *types.Block { return s.finality.Finalized() }

// KeyAddress devuelve la dirección del validador local (cero si no hay).
func (s *Service) KeyAddress() types.Address {
	if s.cfg.Key == nil {
		return types.Address{}
	}
	return s.cfg.Key.Address
}

// Ensure mempool.Service puede actuar como TxSource.
var _ TxSource = (*mempool.Service)(nil)

// Ensure storage tipado.

// BlockReader permite reconstruir el árbol de consenso desde la cadena
// canónica persistida (reinicio del nodo).
type BlockReader interface {
	CurrentBlock() *types.Block
	BlockByNumber(n uint64) (*types.Block, error)
}

// BootstrapFromStore rellena el BlockTree con los bloques canónicos ya
// persistidos, reaplica los QC embebidos en Justify y, si el tip aún no
// tiene QC pero este nodo puede formar quórum solo (N=1 típico en tests),
// emite un QC de autocertificación. Tras esto el pacemaker queda en
// highQC.View+1 y puede seguir proponiendo sin re-votar vistas viejas.
// Debe llamarse ANTES de Start().
func (s *Service) BootstrapFromStore(chain BlockReader) error {
	if chain == nil {
		return nil
	}
	head := chain.CurrentBlock()
	if head == nil {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Evitar que ProcessQC dispare propuestas mientras aún no hemos
	// arrancado (OnNewView spawnea goroutines que miran s.running).
	prevNewView := s.pace.OnNewView
	s.pace.OnNewView = nil
	defer func() { s.pace.OnNewView = prevNewView }()

	var tipQC *QuorumCert
	for n := uint64(1); n <= head.Number(); n++ {
		b, err := chain.BlockByNumber(n)
		if err != nil {
			return err
		}
		if b == nil {
			return fmt.Errorf("consenso: falta bloque canónico #%d al reiniciar", n)
		}
		if err := s.tree.Insert(b); err != nil {
			return err
		}
		if j := b.Justify(); len(j) > 0 {
			qc, err := DecodeQuorumCert(j)
			if err != nil {
				continue
			}
			s.safety.Round().UpdateHighQC(qc)
			_, _ = s.finality.ProcessQC(qc)
			tipQC = qc
		}
	}

	// Autocertificar el tip si falta su QC y formamos quórum en solitario.
	tip := head
	if s.tree.QCFor(tip.Hash()) == nil && s.cfg.Key != nil {
		info, err := s.epochs.ForBlock(tip.Number())
		if err == nil {
			_, val := info.Validators.ByAddress(s.cfg.Key.Address)
			if val != nil && info.Validators.HasQuorum(val.Power) {
				h := tip.HeaderRef()
				vote, err := NewVote(s.cfg.Key, s.cfg.ChainID, VoteData{
					Epoch: h.Epoch, View: h.View, BlockNumber: h.Number, BlockHash: tip.Hash(),
				})
				if err == nil {
					if qc, err := AggregateVotes(info.Validators, []*Vote{vote}); err == nil {
						s.safety.Round().UpdateHighQC(qc)
						_, _ = s.finality.ProcessQC(qc)
						tipQC = qc
					}
				}
			}
		}
	}

	if tipQC == nil {
		tipQC = s.tree.HighQC()
	}
	if tipQC != nil {
		s.pace.ProcessQC(tipQC)
	}

	// Si el WAL tiene lastVotedView por delante del pacemaker, avanzar
	// artificialmente vía un ProcessQC ya aplicado no basta: forzar vista.
	snap := s.safety.Round().Snapshot()
	target := snap.LastVotedView + 1
	if tipQC != nil && tipQC.View+1 > target {
		target = tipQC.View + 1
	}
	if s.pace.View() < target {
		// Reutilizar ProcessQC no sube sin QC mayor; avanzamos el reloj
		// interno creando un QC sintético imposible... mejor: SetView.
		s.pace.forceView(target)
	}
	return nil
}

var _ BlockCommitter = (*storage.BlockStore)(nil)

// crypto import used by VRF path via ValidatorKey.
var _ = crypto.Keccak256
