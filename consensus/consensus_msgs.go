package consensus

// Este archivo define el formato de cable de los mensajes de consenso:
//
//	mensaje = tipo (1 byte) || RLP(contenido)
//
// El byte de tipo permite despachar sin decodificar y que la capa de red
// (Día 11+) aplique límites y prioridades distintos por tipo. Cada
// contenido reutiliza la codificación canónica de su estructura, de modo
// que un mismo voto o QC tiene siempre los mismos bytes (útil para
// deduplicar por hash en el gossip).
//
// Además de los mensajes del protocolo (propuesta, voto, timeout, TC, QC)
// se incluyen evidencia de doble voto y una petición/respuesta mínima de
// sincronización de bloques certificados para validadores rezagados.

import (
	"errors"
	"fmt"

	"github.com/l1/l1/crypto"
	"github.com/l1/l1/types"
)

// MsgType identifica el tipo de mensaje.
type MsgType byte

// Tipos de mensaje.
const (
	MsgProposal     MsgType = 1
	MsgVote         MsgType = 2
	MsgTimeout      MsgType = 3
	MsgTimeoutCert  MsgType = 4
	MsgQuorumCert   MsgType = 5
	MsgEvidence     MsgType = 6
	MsgSyncRequest  MsgType = 7
	MsgSyncResponse MsgType = 8
)

// Límites de tamaño.
const (
	// MaxMessageSize acota cualquier mensaje (una propuesta lleva un
	// bloque completo, de ahí el margen).
	MaxMessageSize = 16 << 20
	// MaxSyncBlocks acota los bloques por respuesta de sincronización.
	MaxSyncBlocks = 128
)

// Errores de codificación.
var (
	ErrEmptyMessage   = errors.New("consenso: mensaje vacío")
	ErrMessageTooBig  = errors.New("consenso: mensaje demasiado grande")
	ErrUnknownMsgType = errors.New("consenso: tipo de mensaje desconocido")
)

// String devuelve el nombre del tipo.
func (t MsgType) String() string {
	switch t {
	case MsgProposal:
		return "propuesta"
	case MsgVote:
		return "voto"
	case MsgTimeout:
		return "timeout"
	case MsgTimeoutCert:
		return "tc"
	case MsgQuorumCert:
		return "qc"
	case MsgEvidence:
		return "evidencia"
	case MsgSyncRequest:
		return "sync-req"
	case MsgSyncResponse:
		return "sync-resp"
	}
	return fmt.Sprintf("tipo(%d)", byte(t))
}

// SyncRequest pide Count bloques certificados desde la altura From.
type SyncRequest struct {
	From  uint64
	Count uint64
}

// EncodeRLP codifica [from, count].
func (r *SyncRequest) EncodeRLP() []byte {
	return types.EncodeList(types.EncodeUint(r.From), types.EncodeUint(r.Count))
}

// SyncResponse devuelve bloques consecutivos y el QC que certifica al
// último (el justify de cada bloque certifica a su predecesor).
type SyncResponse struct {
	Blocks []*types.Block
	QC     *QuorumCert
}

// EncodeRLP codifica [[bloques...], qc].
func (r *SyncResponse) EncodeRLP() []byte {
	bs := make([][]byte, len(r.Blocks))
	for i, b := range r.Blocks {
		bs[i] = b.EncodeRLP()
	}
	qc := types.EncodeBytes(nil)
	if r.QC != nil {
		qc = r.QC.EncodeRLP()
	}
	return types.EncodeList(types.EncodeList(bs...), qc)
}

// EncodeMessage serializa un mensaje soportado.
func EncodeMessage(msg any) ([]byte, error) {
	var (
		t    MsgType
		body []byte
	)
	switch m := msg.(type) {
	case *Proposal:
		t, body = MsgProposal, m.EncodeRLP()
	case *Vote:
		t, body = MsgVote, m.EncodeRLP()
	case *TimeoutMsg:
		t, body = MsgTimeout, m.EncodeRLP()
	case *TimeoutCert:
		t, body = MsgTimeoutCert, m.EncodeRLP()
	case *QuorumCert:
		t, body = MsgQuorumCert, m.EncodeRLP()
	case *DoubleVoteEvidence:
		t, body = MsgEvidence, m.EncodeRLP()
	case *SyncRequest:
		t, body = MsgSyncRequest, m.EncodeRLP()
	case *SyncResponse:
		if len(m.Blocks) > MaxSyncBlocks {
			return nil, fmt.Errorf("%w: %d bloques", ErrMessageTooBig, len(m.Blocks))
		}
		t, body = MsgSyncResponse, m.EncodeRLP()
	default:
		return nil, fmt.Errorf("%w: %T", ErrUnknownMsgType, msg)
	}
	if len(body)+1 > MaxMessageSize {
		return nil, ErrMessageTooBig
	}
	out := make([]byte, 0, len(body)+1)
	out = append(out, byte(t))
	return append(out, body...), nil
}

// MessageType devuelve el tipo sin decodificar el contenido.
func MessageType(b []byte) (MsgType, error) {
	if len(b) == 0 {
		return 0, ErrEmptyMessage
	}
	return MsgType(b[0]), nil
}

// MessageID es el hash del mensaje serializado (para deduplicar).
func MessageID(b []byte) types.Hash { return crypto.Keccak256Hash(b) }

// DecodeMessage deserializa un mensaje; devuelve el tipo y un puntero a la
// estructura correspondiente.
func DecodeMessage(b []byte) (MsgType, any, error) {
	t, err := MessageType(b)
	if err != nil {
		return 0, nil, err
	}
	if len(b) > MaxMessageSize {
		return t, nil, ErrMessageTooBig
	}
	body := b[1:]
	var msg any
	switch t {
	case MsgProposal:
		msg, err = DecodeProposal(body)
	case MsgVote:
		msg, err = DecodeVote(body)
	case MsgTimeout:
		msg, err = DecodeTimeoutMsg(body)
	case MsgTimeoutCert:
		msg, err = DecodeTimeoutCert(body)
	case MsgQuorumCert:
		msg, err = DecodeQuorumCert(body)
	case MsgEvidence:
		msg, err = DecodeDoubleVoteEvidence(body)
	case MsgSyncRequest:
		msg, err = decodeSyncRequest(body)
	case MsgSyncResponse:
		msg, err = decodeSyncResponse(body)
	default:
		return t, nil, fmt.Errorf("%w: %d", ErrUnknownMsgType, byte(t))
	}
	if err != nil {
		return t, nil, fmt.Errorf("consenso: decodificando %s: %w", t, err)
	}
	return t, msg, nil
}

// decodeSyncRequest es la inversa de SyncRequest.EncodeRLP.
func decodeSyncRequest(b []byte) (*SyncRequest, error) {
	it, err := types.DecodeRLP(b)
	if err != nil {
		return nil, err
	}
	f, err := it.ListN(2)
	if err != nil {
		return nil, err
	}
	r := &SyncRequest{}
	if r.From, err = f[0].Uint64(); err != nil {
		return nil, err
	}
	if r.Count, err = f[1].Uint64(); err != nil {
		return nil, err
	}
	if r.Count > MaxSyncBlocks {
		return nil, fmt.Errorf("%w: pide %d bloques", ErrMessageTooBig, r.Count)
	}
	return r, nil
}

// decodeSyncResponse es la inversa de SyncResponse.EncodeRLP.
func decodeSyncResponse(b []byte) (*SyncResponse, error) {
	it, err := types.DecodeRLP(b)
	if err != nil {
		return nil, err
	}
	f, err := it.ListN(2)
	if err != nil {
		return nil, err
	}
	items, err := f[0].Items()
	if err != nil {
		return nil, err
	}
	if len(items) > MaxSyncBlocks {
		return nil, fmt.Errorf("%w: %d bloques", ErrMessageTooBig, len(items))
	}
	r := &SyncResponse{Blocks: make([]*types.Block, len(items))}
	for i, bi := range items {
		if r.Blocks[i], err = types.DecodeBlock(bi.Raw); err != nil {
			return nil, err
		}
	}
	if f[1].IsList() {
		if r.QC, err = decodeQCItem(f[1]); err != nil {
			return nil, err
		}
	} else if len(f[1].Data) != 0 {
		return nil, errors.New("consenso: QC de sincronización mal formado")
	}
	return r, nil
}
