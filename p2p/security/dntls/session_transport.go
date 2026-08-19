package dntls

import (
	"context"
	"net"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/core/sec"
	"github.com/libp2p/go-libp2p/p2p/canonicallog"
	"github.com/libp2p/go-libp2p/p2p/security/dntls/pb"

	manet "github.com/multiformats/go-multiaddr/net"
)

// SessionOption configures per-connection handshake behavior.
type SessionOption = func(*SessionTransport) error

// Prologue sets a prologue for the Noise session.
// The handshake will only complete successfully if both parties set the same
// prologue.
func Prologue(prologue []byte) SessionOption {
	return func(s *SessionTransport) error {
		s.prologue = prologue
		return nil
	}
}

// EarlyDataHandler defines application payload for handshake messages.
type EarlyDataHandler interface {
	Send(context.Context, net.Conn, peer.ID) *pb.NoiseExtensions
	Received(context.Context, net.Conn, *pb.NoiseExtensions) error
}

// EarlyData sets the EarlyDataHandler for the initiator and responder roles.
func EarlyData(initiator, responder EarlyDataHandler) SessionOption {
	return func(s *SessionTransport) error {
		s.initiatorEarlyDataHandler = initiator
		s.responderEarlyDataHandler = responder
		return nil
	}
}

// DisablePeerIDCheck disables checking the remote peer ID. This is
// susceptible to MITM attacks since we do not verify the identity of
// the remote peer.
func DisablePeerIDCheck() SessionOption {
	return func(s *SessionTransport) error {
		s.disablePeerIDCheck = true
		return nil
	}
}

var _ sec.SecureTransport = &SessionTransport{}

// SessionTransport wraps a Transport with per-connection options.
type SessionTransport struct {
	t *Transport

	prologue           []byte
	disablePeerIDCheck bool
	protocolID         protocol.ID

	initiatorEarlyDataHandler, responderEarlyDataHandler EarlyDataHandler
}

// SecureInbound runs the DNTLS-Noise handshake as the responder.
func (st *SessionTransport) SecureInbound(ctx context.Context, insecure net.Conn, p peer.ID) (sec.SecureConn, error) {
	checkPeerID := !st.disablePeerIDCheck && p != ""
	c, err := newSecureSession(st.t, ctx, insecure, p, st.prologue, st.initiatorEarlyDataHandler, st.responderEarlyDataHandler, false, checkPeerID)
	if err != nil {
		addr, maErr := manet.FromNetAddr(insecure.RemoteAddr())
		if maErr == nil {
			canonicallog.LogPeerStatus(100, p, addr, "handshake_failure", "dntls", "err", err.Error())
		}
	}
	return c, err
}

// SecureOutbound runs the DNTLS-Noise handshake as the initiator.
func (st *SessionTransport) SecureOutbound(ctx context.Context, insecure net.Conn, p peer.ID) (sec.SecureConn, error) {
	return newSecureSession(st.t, ctx, insecure, p, st.prologue, st.initiatorEarlyDataHandler, st.responderEarlyDataHandler, true, !st.disablePeerIDCheck)
}

func (st *SessionTransport) ID() protocol.ID { return st.protocolID }
