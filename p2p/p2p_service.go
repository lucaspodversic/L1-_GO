package p2p

// P2PService ensambla transporte, conexiones, gossip, sync y discovery.

import (
	"context"
	"sync"

	"github.com/l1/l1/types"
)

// Service es el fachada de red del nodo.
type Service struct {
	mu        sync.Mutex
	transport *Transport
	conns     *ConnManager
	gossip    *Gossip
	blocks    *BlockPropagator
	txs       *TxPropagator
	rr        *ReqResp
	dht       *Kademlia
	store     *PeerStore
	bans      *BanList
	scorer    *Scorer
	nat       *NATManager
	syncer    *SyncManager
	bootnodes []Bootnode

	headers HeaderProvider
	bodies  BodyProvider
	state   StateNodeProvider

	onConsensus func(from PeerID, msg []byte)
	running     bool
	cancel      context.CancelFunc
	wg          sync.WaitGroup
}

// ServiceConfig configura el servicio.
type ServiceConfig struct {
	ListenAddr string
	Bootnodes  []Bootnode
	PeerStore  string
	MaxPeers   int
}

// NewService construye el servicio (aún no escucha).
func NewService(id *LocalIdentity, cfg ServiceConfig) *Service {
	tr := NewTransport(id)
	bans := NewBanList()
	cmCfg := DefaultConnManagerConfig()
	if cfg.MaxPeers > 0 {
		cmCfg.MaxInbound = cfg.MaxPeers
		cmCfg.MaxOutbound = cfg.MaxPeers / 2
	}
	cm := NewConnManager(tr, bans, cmCfg)
	s := &Service{
		transport: tr, conns: cm, bans: bans,
		store:     NewPeerStore(cfg.PeerStore),
		scorer:    NewScorer(DefaultScoreConfig()),
		nat:       NewNATManager(),
		dht:       NewKademlia(id.ID),
		bootnodes: cfg.Bootnodes,
	}
	s.gossip = NewGossip(cm.Send, cm.Peers)
	s.blocks = NewBlockPropagator(s.gossip)
	s.txs = NewTxPropagator(s.gossip)
	s.rr = NewReqResp(cm.Send, 0)
	cm.OnMessage(s.dispatch)
	return s
}

// SetChainProviders inyecta las fuentes de sync.
func (s *Service) SetChainProviders(h HeaderProvider, b BodyProvider, st StateNodeProvider, w ChainWriter) {
	s.headers, s.bodies, s.state = h, b, st
	if w != nil {
		s.syncer = NewSyncManager(w, s.rr)
	}
}

// OnConsensus registra el handler de mensajes de consenso (topic).
func (s *Service) OnConsensus(h func(PeerID, []byte)) {
	s.onConsensus = h
	s.gossip.Subscribe(TopicConsensus, func(from PeerID, _ string, data []byte) {
		if h != nil {
			h(from, data)
		}
	})
}

// BroadcastConsensus difunde un mensaje de consenso.
func (s *Service) BroadcastConsensus(msg []byte) error {
	return s.gossip.Publish(TopicConsensus, msg, PeerID{})
}

// Broadcast implementa consensus.Broadcaster (ignora SendTo fino).
func (s *Service) Broadcast(msg []byte) error { return s.BroadcastConsensus(msg) }

// SendTo envía a un peer si conocemos su ID (por ahora broadcast).
func (s *Service) SendTo(_ types.Address, msg []byte) error { return s.BroadcastConsensus(msg) }

// Gossip/Tx/Blocks accessors.
func (s *Service) Gossip() *Gossip                   { return s.gossip }
func (s *Service) TxPropagator() *TxPropagator       { return s.txs }
func (s *Service) BlockPropagator() *BlockPropagator { return s.blocks }
func (s *Service) ConnManager() *ConnManager         { return s.conns }
func (s *Service) Identity() *LocalIdentity          { return s.transport.Identity() }
func (s *Service) PeerCount() int                    { return s.conns.Len() }

// Start escucha y conecta bootnodes.
func (s *Service) Start(listen string) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return nil
	}
	if err := s.transport.Listen(listen); err != nil {
		s.mu.Unlock()
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.running = true
	s.mu.Unlock()

	s.wg.Add(1)
	go s.acceptLoop()

	for _, b := range s.bootnodes {
		bb := b
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			_, _ = s.conns.DialAndAdd(ctx, bb.Addr)
		}()
	}
	return nil
}

// ListenAddr dirección de escucha.
func (s *Service) ListenAddr() string {
	a := s.transport.Addr()
	if a == nil {
		return ""
	}
	return a.String()
}

func (s *Service) acceptLoop() {
	defer s.wg.Done()
	for {
		c, err := s.transport.Accept()
		if err != nil {
			return
		}
		s.conns.AddInbound(c)
		s.dht.Upsert(DHTNode{ID: c.RemoteID(), Addr: c.RemoteAddr().String()})
		s.store.Upsert(PeerRecord{ID: c.RemoteID(), Addrs: []string{c.RemoteAddr().String()}})
	}
}

func (s *Service) dispatch(from PeerID, msg []byte) {
	t, payload, err := DecodeApp(msg)
	if err != nil {
		return
	}
	switch t {
	case AppGossip:
		s.gossip.Handle(from, payload)
	case AppPing:
		_ = s.conns.Send(from, EncodePong(payload))
	case AppPong:
		// RTT disponible vía PingRTT(payload)
	case AppReq:
		s.rr.HandleReq(from, payload, s.handleRequest)
	case AppResp:
		s.rr.HandleResp(payload)
	case AppSync:
		s.handleSync(from, payload)
	case AppFindNode:
		if len(payload) >= 32 {
			target := types.BytesToHash(payload[:32])
			nodes := s.dht.Closest(target, kBucketSize)
			_ = s.conns.Send(from, EncodeApp(AppNeighbors, EncodeNeighbors(nodes)[1:]))
		}
	}
}

func (s *Service) handleRequest(body []byte) []byte {
	// body puede ser un AppSync get*
	if len(body) == 0 {
		return nil
	}
	return s.serveSync(body)
}

func (s *Service) handleSync(from PeerID, payload []byte) {
	if len(payload) == 0 {
		return
	}
	switch SyncMsgType(payload[0]) {
	case SyncStatus:
		st, err := DecodeStatus(payload)
		if err == nil && s.syncer != nil {
			s.syncer.HandleStatus(from, st)
		}
	default:
		resp := s.serveSync(payload)
		if resp != nil {
			_ = s.conns.Send(from, resp)
		}
	}
}

func (s *Service) serveSync(payload []byte) []byte {
	if len(payload) == 0 {
		return nil
	}
	switch SyncMsgType(payload[0]) {
	case SyncGetHeaders:
		if s.headers != nil {
			return ServeGetHeaders(s.headers, payload)
		}
	case SyncGetBodies:
		if s.bodies != nil {
			return ServeGetBodies(s.bodies, payload)
		}
	case SyncGetState:
		if s.state != nil {
			return ServeGetState(s.state, payload)
		}
	}
	return nil
}

// Stop detiene el servicio.
func (s *Service) Stop() error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = false
	if s.cancel != nil {
		s.cancel()
	}
	s.mu.Unlock()
	_ = s.transport.Close()
	s.conns.CloseAll()
	_ = s.store.Save()
	s.wg.Wait()
	return nil
}

// AnnounceBlock difunde un hash de bloque.
func (s *Service) AnnounceBlock(h types.Hash) error { return s.blocks.Announce(h) }

// AnnounceTx difunde una tx.
func (s *Service) AnnounceTx(tx *types.Transaction) error { return s.txs.Announce(tx) }
