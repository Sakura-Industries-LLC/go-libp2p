package dntls

import (
	"context"
	"errors"
	"net"
	"slices"

	"github.com/Sakura-Industries-LLC/ProjectCobra/dntls/lib/core"
	dntlscrypto "github.com/Sakura-Industries-LLC/ProjectCobra/dntls/lib/core/crypto"
	dntlstls "github.com/Sakura-Industries-LLC/ProjectCobra/dntls/lib/tls"

	ic "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/core/sec"
	"github.com/libp2p/go-libp2p/p2p/canonicallog"
	tptu "github.com/libp2p/go-libp2p/p2p/net/upgrader"
	"github.com/libp2p/go-libp2p/p2p/security/dntls/pb"

	manet "github.com/multiformats/go-multiaddr/net"
)

// ID is the protocol ID for DNTLS-Noise.
const ID = "/dntls/1.0.0"

const maxProtoNum = 100

// Verifier is the minimal verification interface required by the DNTLS-Noise
// transport. It is intentionally narrower than core.Verifier because the
// handshake only uses VerifyByOuterHash plus network config access.
type Verifier interface {
	VerifyByOuterHash(ctx context.Context, outerHash core.OuterHash, subnameHashes ...core.Subname) (*core.Result, error)
	Config() *core.NetworkConfig
}

// Config configures the DNTLS-Noise security transport.
type Config struct {
	// ServiceKey is the DNTLS service key. Its public component becomes
	// the libp2p identity key: peer.ID = IDFromPublicKey(ServicePub).
	ServiceKey dntlscrypto.SecureKey

	// OuterHash is the current epoch-rotating outer hash (required).
	OuterHash []byte

	// FQDN is the optional plaintext name (e.g., "alice.dntls").
	FQDN string

	// SubnameHashes is required for subname identities when FQDN is
	// absent. Ordered parent-to-child.
	SubnameHashes []core.Subname

	// Verifier performs three-pillar verification. Required (non-nil).
	Verifier Verifier

	// OnPeerVerified is called after successful handshake with the
	// remote PeerIdentity. Returning an error rejects the connection.
	OnPeerVerified func(peer.ID, *dntlstls.PeerIdentity) error
}

// Transport implements sec.SecureTransport using DNTLS-Noise.
type Transport struct {
	protocolID protocol.ID
	localID    peer.ID
	localPub   ic.PubKey
	cfg        Config
	sigAlg     dntlscrypto.SignatureAlg
	muxers     []protocol.ID
}

var _ sec.SecureTransport = &Transport{}

// New creates a new DNTLS-Noise transport.
func New(id protocol.ID, cfg Config, muxers []tptu.StreamMuxer) (*Transport, error) {
	if cfg.ServiceKey == nil {
		return nil, errors.New("dntls: ServiceKey is required")
	}
	if cfg.Verifier == nil {
		return nil, errors.New("dntls: Verifier is required")
	}
	if len(cfg.OuterHash) == 0 {
		return nil, errors.New("dntls: OuterHash is required")
	}

	sigAlg := cfg.Verifier.Config().CryptoSuite.SignatureAlg()

	localPub, err := dntlsPubToLibp2p(cfg.ServiceKey.PublicKey(), sigAlg)
	if err != nil {
		return nil, err
	}

	localID, err := peer.IDFromPublicKey(localPub)
	if err != nil {
		return nil, err
	}

	muxerIDs := make([]protocol.ID, 0, len(muxers))
	for _, m := range muxers {
		muxerIDs = append(muxerIDs, m.ID)
	}

	return &Transport{
		protocolID: id,
		localID:    localID,
		localPub:   localPub,
		cfg:        cfg,
		sigAlg:     sigAlg,
		muxers:     muxerIDs,
	}, nil
}

// SecureInbound runs the DNTLS-Noise handshake as the responder.
func (t *Transport) SecureInbound(ctx context.Context, insecure net.Conn, p peer.ID) (sec.SecureConn, error) {
	responderEDH := newTransportEDH(t)
	c, err := newSecureSession(t, ctx, insecure, p, nil, nil, responderEDH, false, p != "")
	if err != nil {
		addr, maErr := manet.FromNetAddr(insecure.RemoteAddr())
		if maErr == nil {
			canonicallog.LogPeerStatus(100, p, addr, "handshake_failure", "dntls", "err", err.Error())
		}
	}
	return SessionWithConnState(c, responderEDH.MatchMuxers(false)), err
}

// SecureOutbound runs the DNTLS-Noise handshake as the initiator.
func (t *Transport) SecureOutbound(ctx context.Context, insecure net.Conn, p peer.ID) (sec.SecureConn, error) {
	initiatorEDH := newTransportEDH(t)
	c, err := newSecureSession(t, ctx, insecure, p, nil, initiatorEDH, nil, true, true)
	if err != nil {
		return c, err
	}
	return SessionWithConnState(c, initiatorEDH.MatchMuxers(true)), err
}

// WithSessionOptions creates a SessionTransport with per-connection options.
func (t *Transport) WithSessionOptions(opts ...SessionOption) (*SessionTransport, error) {
	st := &SessionTransport{t: t, protocolID: t.protocolID}
	for _, opt := range opts {
		if err := opt(st); err != nil {
			return nil, err
		}
	}
	return st, nil
}

func (t *Transport) ID() protocol.ID { return t.protocolID }

// PeerIdentity extracts the DNTLS PeerIdentity from a completed secure
// connection. Returns nil if the connection is not a DNTLS-Noise session.
func PeerIdentity(conn sec.SecureConn) *dntlstls.PeerIdentity {
	if s, ok := conn.(*secureSession); ok {
		return s.PeerIdentity()
	}
	return nil
}

func matchMuxers(initiatorMuxers, responderMuxers []protocol.ID) protocol.ID {
	for _, m := range initiatorMuxers {
		if slices.Contains(responderMuxers, m) {
			return m
		}
	}
	return ""
}

type transportEarlyDataHandler struct {
	transport      *Transport
	receivedMuxers []protocol.ID
}

var _ EarlyDataHandler = &transportEarlyDataHandler{}

func newTransportEDH(t *Transport) *transportEarlyDataHandler {
	return &transportEarlyDataHandler{transport: t}
}

func (h *transportEarlyDataHandler) Send(context.Context, net.Conn, peer.ID) *pb.NoiseExtensions {
	return &pb.NoiseExtensions{
		StreamMuxers: protocol.ConvertToStrings(h.transport.muxers),
	}
}

func (h *transportEarlyDataHandler) Received(_ context.Context, _ net.Conn, ext *pb.NoiseExtensions) error {
	if ext != nil && len(ext.StreamMuxers) <= maxProtoNum {
		h.receivedMuxers = protocol.ConvertFromStrings(ext.GetStreamMuxers())
	}
	return nil
}

func (h *transportEarlyDataHandler) MatchMuxers(isInitiator bool) protocol.ID {
	if isInitiator {
		return matchMuxers(h.transport.muxers, h.receivedMuxers)
	}
	return matchMuxers(h.receivedMuxers, h.transport.muxers)
}
