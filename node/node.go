package node

// Node es la agregación de todos los servicios en ejecución.

import (
	"context"
	"fmt"
	"sync"

	"github.com/l1/l1/consensus"
	"github.com/l1/l1/execution"
	"github.com/l1/l1/mempool"
	"github.com/l1/l1/p2p"
	"github.com/l1/l1/storage"
	"github.com/l1/l1/types"
)

// Node es el proceso completo.
type Node struct {
	mu       sync.Mutex
	cfg      Config
	log      *Logger
	metrics  *Metrics
	health   *HealthChecker
	bus      *EventBus
	services *ServiceManager

	db        *storage.Database
	chain     *ChainService
	exec      *execution.ExecutorService
	pool      *mempool.Service
	p2p       *p2p.Service
	consensus *consensus.Service
	rpc       *RPCServer

	validator *consensus.ValidatorKey
	identity  *p2p.LocalIdentity
	genesis   *types.Block
	closed    bool
}

// Config expone la config.
func (n *Node) Config() Config { return n.cfg }

// Chain expone la cadena.
func (n *Node) Chain() *ChainService { return n.chain }

// Executor expone el ejecutor.
func (n *Node) Executor() *execution.ExecutorService { return n.exec }

// Mempool expone el pool.
func (n *Node) Mempool() *mempool.Service { return n.pool }

// P2P expone la red.
func (n *Node) P2P() *p2p.Service { return n.p2p }

// Consensus expone el motor.
func (n *Node) Consensus() *consensus.Service { return n.consensus }

// RPC expone el servidor RPC.
func (n *Node) RPC() *RPCServer { return n.rpc }

// Logger expone el logger.
func (n *Node) Logger() *Logger { return n.log }

// Metrics expone métricas.
func (n *Node) Metrics() *Metrics { return n.metrics }

// Health expone el comprobador de salud.
func (n *Node) Health() *HealthChecker { return n.health }

// Events expone el bus.
func (n *Node) Events() *EventBus { return n.bus }

// GenesisHash hash génesis.
func (n *Node) GenesisHash() types.Hash { return n.genesis.Hash() }

// Start arranca todos los servicios.
func (n *Node) Start() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.services.StartAll(); err != nil {
		return err
	}
	n.log.Infof("nodo arrancado; peer=%s rpc=%s p2p=%s",
		p2p.ShortID(n.identity.ID), n.cfg.RPCAddr, n.p2p.ListenAddr())
	return nil
}

// Stop detiene todo.
func (n *Node) Stop() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return nil
	}
	n.closed = true
	err := n.services.StopAll()
	if n.db != nil {
		if e := n.db.Close(); e != nil && err == nil {
			err = e
		}
	}
	n.log.Infof("nodo detenido")
	return err
}

// Wait bloquea hasta señal OS y entonces para.
func (n *Node) Wait() {
	ctx, cancel := WithShutdown(context.Background())
	defer cancel()
	<-ctx.Done()
	_ = n.Stop()
}

// Broadcaster adapta p2p.Service a consensus.Broadcaster.
type p2pBroadcaster struct{ s *p2p.Service }

func (b p2pBroadcaster) Broadcast(msg []byte) error { return b.s.Broadcast(msg) }
func (b p2pBroadcaster) SendTo(addr types.Address, msg []byte) error {
	return b.s.SendTo(addr, msg)
}

// AttachConsensusHandlers enlaza gossip de consenso al motor.
func (n *Node) AttachConsensusHandlers() {
	if n.p2p == nil || n.consensus == nil {
		return
	}
	n.p2p.OnConsensus(func(_ p2p.PeerID, msg []byte) {
		_ = n.consensus.HandleMessage(types.Address{}, msg)
	})
	n.consensus.OnCommit = func(blocks []*types.Block, _ *consensus.QuorumCert) {
		for _, b := range blocks {
			n.metrics.BlocksFinalized.Add(1)
			n.health.SetFinalized(b.Number())
			n.health.SetHead(b.Number())
			n.bus.Publish(EventFinalized, b)
			n.bus.Publish(EventNewHead, b.HeaderRef())
			_ = n.p2p.AnnounceBlock(b.Hash())
		}
	}
}

var _ = fmt.Sprintf
