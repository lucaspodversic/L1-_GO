package node

// Builder: cablea almacenamiento, génesis, mempool, ejecución, P2P, consenso y RPC.

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/l1/l1/consensus"
	"github.com/l1/l1/crypto"
	"github.com/l1/l1/execution"
	"github.com/l1/l1/mempool"
	"github.com/l1/l1/p2p"
	"github.com/l1/l1/storage"
	"github.com/l1/l1/types"
)

// Builder construye un Node a partir de Config.
type Builder struct {
	cfg Config
	log *Logger
}

// NewBuilder crea el builder.
func NewBuilder(cfg Config) *Builder {
	lvl := ParseLevel(cfg.LogLevel)
	return &Builder{cfg: cfg, log: NewLogger(os.Stderr, lvl)}
}

// Build abre la DB, cablea servicios y devuelve el nodo (aún no arrancado).
func (b *Builder) Build() (*Node, error) {
	cfg := b.cfg
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return nil, err
	}

	db, err := storage.Open(storage.DefaultConfig(filepath.Join(cfg.DataDir, "chain")))
	if err != nil {
		return nil, fmt.Errorf("node: abrir db: %w", err)
	}

	genesis, gspec, err := b.loadOrCommitGenesis(db)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	cfg.ChainID = gspec.ChainID

	identity, err := b.loadOrCreateIdentity()
	if err != nil {
		_ = db.Close()
		return nil, err
	}

	var valKey *consensus.ValidatorKey
	if cfg.Mine {
		valKey, err = b.loadValidatorKey(gspec)
		if err != nil {
			_ = db.Close()
			return nil, err
		}
	}

	chain := NewChainService(db, genesis)
	metrics := NewMetrics()
	health := &HealthChecker{}
	bus := NewEventBus()
	services := NewServiceManager(b.log)

	// Ejecución.
	reward := &consensus.RewardFinalizer{Params: consensus.DefaultRewardParams()}
	proc := execution.NewBlockProcessor(execution.DefaultChainConfig(cfg.ChainID), chain, execution.Config{}, reward)
	exec := execution.NewExecutorService(proc, db.State, chain)

	// Mempool.
	head := chain.CurrentHeader()
	st, err := chain.StateAt(head.StateRoot)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	pool := mempool.New(mempool.DefaultConfig(cfg.ChainID), head, st)
	mpSrc := mempoolChain{c: chain}
	mpSvc := mempool.NewService(pool, mpSrc, mempool.ServiceConfig{EvictInterval: time.Minute, HeadBuffer: 16})

	// P2P.
	p2pCfg := p2p.ServiceConfig{
		ListenAddr: cfg.ListenAddr,
		Bootnodes:  mustBootnodes(cfg.Bootnodes),
		MaxPeers:   50,
	}
	p2pSvc := p2p.NewService(identity, p2pCfg)
	p2pSvc.SetChainProviders(chain, chain, db.Nodes, chain)

	// Consenso.
	vset, err := consensus.ValidatorSetFromGenesis(gspec.Validators)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	ep := consensus.EpochParams{Length: gspec.Consensus.EpochLength}
	if ep.Length == 0 {
		ep = consensus.DefaultEpochParams()
	}
	epochs := consensus.NewEpochManager(ep, consensus.DefaultStakingParams(), genesis.HeaderRef(), vset, 8)
	reward.Sets = epochs

	walDir := filepath.Join(cfg.DataDir, "consensus-wal")
	wal, err := consensus.OpenConsensusWAL(walDir)
	if err != nil {
		_ = db.Close()
		return nil, err
	}

	blockTime := time.Duration(cfg.BlockTimeMs) * time.Millisecond
	if blockTime <= 0 {
		blockTime = time.Duration(gspec.Consensus.BlockTimeMs) * time.Millisecond
	}
	csCfg := consensus.ServiceConfig{
		ChainID: cfg.ChainID, Key: valKey, BlockTime: blockTime, GasLimit: gspec.GasLimit,
	}
	eng, err := consensus.NewService(csCfg, genesis, epochs, exec, chain.Blocks(), mpSvc, p2pBroadcaster{p2pSvc}, wal, reward)
	if err != nil {
		_ = wal.Close()
		_ = db.Close()
		return nil, err
	}

	n := &Node{
		cfg: cfg, log: b.log, metrics: metrics, health: health, bus: bus, services: services,
		db: db, chain: chain, exec: exec, pool: mpSvc, p2p: p2pSvc, consensus: eng,
		validator: valKey, identity: identity, genesis: genesis,
	}
	n.rpc = NewRPCServer(n)
	n.AttachConsensusHandlers()
	// Reconstruir árbol/QC desde la cadena persistida (reinicios).
	if err := eng.BootstrapFromStore(chain.Blocks()); err != nil {
		_ = wal.Close()
		_ = db.Close()
		return nil, err
	}

	httpSrv := NewHTTPServer(n.rpc, cfg.RPCAddr)
	wsSrv := NewWSServer(n.rpc, cfg.RPCWSAddr)

	services.Register("mempool", LifecycleFunc{
		StartFunc: func() error { mpSvc.Start(); return nil },
		StopFunc:  func() error { mpSvc.Stop(); return nil },
	})
	services.Register("p2p", LifecycleFunc{
		StartFunc: func() error { return p2pSvc.Start(cfg.ListenAddr) },
		StopFunc:  func() error { return p2pSvc.Stop() },
	})
	services.Register("consensus", eng)
	services.Register("rpc-http", LifecycleFunc{
		StartFunc: func() error {
			if err := httpSrv.Start(); err != nil {
				return err
			}
			n.cfg.RPCAddr = httpSrv.Addr()
			b.log.Infof("RPC HTTP en %s", n.cfg.RPCAddr)
			return nil
		},
		StopFunc: func() error { return httpSrv.Stop() },
	})
	services.Register("rpc-ws", LifecycleFunc{
		StartFunc: func() error {
			if err := wsSrv.Start(); err != nil {
				return err
			}
			n.cfg.RPCWSAddr = wsSrv.Addr()
			b.log.Infof("RPC WS en %s", n.cfg.RPCWSAddr)
			return nil
		},
		StopFunc: func() error { return wsSrv.Stop() },
	})
	services.Register("wal", LifecycleFunc{
		StopFunc: func() error { return wal.Close() },
	})

	return n, nil
}

// mempoolChain adapta ChainService a mempool.ChainSource.
type mempoolChain struct{ c *ChainService }

func (m mempoolChain) CurrentHeader() *types.Header { return m.c.CurrentHeader() }
func (m mempoolChain) StateAt(root types.Hash) (mempool.StateReader, error) {
	return m.c.StateAt(root)
}

func (b *Builder) loadOrCommitGenesis(db *storage.Database) (*types.Block, *types.Genesis, error) {
	if spec, err := storage.ReadGenesisSpec(db.KV); err == nil && spec != nil {
		block, err := db.Blocks.BlockByNumber(0)
		if err != nil {
			return nil, nil, err
		}
		return block, spec, nil
	}
	gspec, err := b.resolveGenesisSpec()
	if err != nil {
		return nil, nil, err
	}
	block, err := storage.CommitGenesis(gspec, db.State, db.Blocks)
	if err != nil {
		return nil, nil, err
	}
	return block, gspec, nil
}

func (b *Builder) resolveGenesisSpec() (*types.Genesis, error) {
	if b.cfg.GenesisFile != "" {
		return types.LoadGenesis(b.cfg.GenesisFile)
	}
	// Dev: génesis con validador local si hay clave; si no, genera una efímera
	// (sólo útil en memoria / primer arranque sin init).
	path := b.cfg.ValidatorKey
	if path == "" {
		path = filepath.Join(b.cfg.DataDir, "validator.key")
	}
	var vk *consensus.ValidatorKey
	var err error
	if _, err = os.Stat(path); err == nil {
		vk, err = consensus.LoadValidatorKey(path, "")
		if err != nil {
			// probar passphrase vacía ya falló; intentar sin cifrar no aplica
			return nil, fmt.Errorf("node: cargar validador: %w", err)
		}
	} else {
		addr := types.Address{} // se rellena abajo con clave secp ficticia
		funded, _ := crypto.GenerateSecp256k1(rand.Reader)
		addr = funded.Address()
		vk, err = consensus.GenerateValidatorKey(addr, nil)
		if err != nil {
			return nil, err
		}
		_ = os.MkdirAll(filepath.Dir(path), 0o755)
		if err := consensus.SaveValidatorKey(path, vk, "", 2 /*scryptN bajo*/); err != nil {
			return nil, err
		}
		b.cfg.ValidatorKey = path
	}
	gv, err := consensus.GenesisValidatorFromKey(vk, 1)
	if err != nil {
		return nil, err
	}
	g := types.DefaultDevGenesis(vk.Address, gv)
	// Época larga para smoke/dev sin rotación.
	g.Consensus.EpochLength = 1_000_000
	return g, nil
}

func (b *Builder) loadOrCreateIdentity() (*p2p.LocalIdentity, error) {
	path := b.cfg.NodeKey
	if path == "" {
		path = filepath.Join(b.cfg.DataDir, "nodekey")
	}
	if _, err := os.Stat(path); err == nil {
		priv, err := crypto.LoadKeyFile(path, "")
		if err != nil {
			return nil, err
		}
		ek, ok := priv.(*crypto.Ed25519PrivateKey)
		if !ok {
			return nil, fmt.Errorf("node: nodekey no es Ed25519")
		}
		return p2p.IdentityFromPrivate(ek), nil
	}
	id, err := p2p.NewLocalIdentity()
	if err != nil {
		return nil, err
	}
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	if err := crypto.SaveKeyFile(path, id.Private, "", 2); err != nil {
		return nil, err
	}
	b.cfg.NodeKey = path
	return id, nil
}

func (b *Builder) loadValidatorKey(gspec *types.Genesis) (*consensus.ValidatorKey, error) {
	path := b.cfg.ValidatorKey
	if path == "" {
		path = filepath.Join(b.cfg.DataDir, "validator.key")
	}
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("node: falta clave de validador (%s); ejecuta `l1 init`", path)
	}
	vk, err := consensus.LoadValidatorKey(path, "")
	if err != nil {
		return nil, err
	}
	return vk, nil
}

func mustBootnodes(s string) []p2p.Bootnode {
	if s == "" {
		return nil
	}
	list, err := p2p.ParseBootnodeList(s)
	if err != nil {
		return nil
	}
	return list
}
