// Package dntls defines the contract between go-libp2p's transports and an
// externally provided DNTLS-Noise security transport.
//
// This package deliberately contains no DNTLS implementation. It carries only
// the seam types the patched transports (WebTransport, WebRTC) program
// against: the Transport interface, per-session options, the early-data
// handler contract, and the Noise extensions wire type in the pb subpackage.
// The implementation lives in the DNTLS SDK and is injected at host
// construction time. QUIC uses the sibling dntlscfg.Provider seam instead,
// because it consumes *tls.Config rather than a Noise session.
package dntls

import (
	"context"
	"net"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/sec"
	"github.com/libp2p/go-libp2p/p2p/security/dntls/pb"
)

// EarlyDataHandler defines application payload for handshake messages.
// Implementations exchange pb.NoiseExtensions during the handshake, for
// example WebTransport certificate hashes or stream-muxer preferences.
type EarlyDataHandler interface {
	// Send returns the extensions to attach to the handshake message
	// destined for the given peer.
	Send(context.Context, net.Conn, peer.ID) *pb.NoiseExtensions
	// Received processes extensions attached to a received handshake
	// message. Returning an error aborts the handshake.
	Received(context.Context, net.Conn, *pb.NoiseExtensions) error
}

// SessionParams holds per-connection handshake parameters assembled by
// SessionOption values. Implementations of Transport read the resulting
// struct when building a session-scoped secure transport.
type SessionParams struct {
	// Prologue is the Noise prologue; both parties must set the same
	// value for the handshake to complete.
	Prologue []byte
	// DisablePeerIDCheck skips verification of the remote peer ID.
	// Susceptible to MITM when set; used where the peer ID is not yet
	// known, for example inbound WebRTC before identification.
	DisablePeerIDCheck bool
	// Initiator handles early data when this side initiates.
	Initiator EarlyDataHandler
	// Responder handles early data when this side responds.
	Responder EarlyDataHandler
}

// SessionOption configures per-connection handshake behavior.
type SessionOption func(*SessionParams) error

// Prologue sets a prologue for the Noise session. The handshake will only
// complete successfully if both parties set the same prologue.
func Prologue(prologue []byte) SessionOption {
	return func(p *SessionParams) error {
		p.Prologue = prologue
		return nil
	}
}

// EarlyData sets the EarlyDataHandler for the initiator and responder roles.
// Either handler may be nil.
func EarlyData(initiator, responder EarlyDataHandler) SessionOption {
	return func(p *SessionParams) error {
		p.Initiator = initiator
		p.Responder = responder
		return nil
	}
}

// DisablePeerIDCheck disables checking the remote peer ID. This is
// susceptible to MITM attacks since we do not verify the identity of the
// remote peer.
func DisablePeerIDCheck() SessionOption {
	return func(p *SessionParams) error {
		p.DisablePeerIDCheck = true
		return nil
	}
}

// Transport is a DNTLS-Noise security transport with per-session
// configuration. The DNTLS SDK provides the implementation; the patched
// WebTransport and WebRTC transports consume it.
type Transport interface {
	sec.SecureTransport

	// WithSessionOptions returns a secure transport specialized with
	// per-connection parameters such as a prologue or early-data handlers.
	WithSessionOptions(opts ...SessionOption) (sec.SecureTransport, error)
}
