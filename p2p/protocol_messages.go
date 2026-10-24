package p2p

// Tipos de mensaje del protocolo de aplicación (encima del transporte).

import "fmt"

// AppMsgType identifica el payload de aplicación.
type AppMsgType byte

const (
	AppGossip        AppMsgType = 1
	AppReq           AppMsgType = 2
	AppResp          AppMsgType = 3
	AppPing          AppMsgType = 4
	AppPong          AppMsgType = 5
	AppFindNode      AppMsgType = 6
	AppNeighbors     AppMsgType = 7
	AppBlockAnnounce AppMsgType = 8
	AppTxAnnounce    AppMsgType = 9
	AppSync          AppMsgType = 10
)

// String para logs.
func (t AppMsgType) String() string {
	switch t {
	case AppGossip:
		return "gossip"
	case AppReq:
		return "req"
	case AppResp:
		return "resp"
	case AppPing:
		return "ping"
	case AppPong:
		return "pong"
	case AppFindNode:
		return "findnode"
	case AppNeighbors:
		return "neighbors"
	case AppBlockAnnounce:
		return "block"
	case AppTxAnnounce:
		return "tx"
	case AppSync:
		return "sync"
	}
	return fmt.Sprintf("app(%d)", t)
}

// Topics de gossip conocidos.
const (
	TopicBlocks    = "blocks"
	TopicTxs       = "txs"
	TopicConsensus = "consensus"
	TopicEvidence  = "evidence"
)
