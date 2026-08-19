// Package noisewrap adapts the stock Noise security transport to the
// dntls.Transport seam.
//
// It performs no DNTLS verification: peers authenticate exactly as with
// upstream go-libp2p Noise. It exists so transports programmed against the
// dntls seam (WebTransport, WebRTC) can run in this repository's tests and
// tooling without a DNTLS stack. Production DNTLS hosts must inject the
// SDK's implementation instead.
package noisewrap

import (
	"context"
	"net"

	ic "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/libp2p/go-libp2p/core/sec"
	"github.com/libp2p/go-libp2p/p2p/security/dntls"
	dntlspb "github.com/libp2p/go-libp2p/p2p/security/dntls/pb"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	noisepb "github.com/libp2p/go-libp2p/p2p/security/noise/pb"

	tptu "github.com/libp2p/go-libp2p/p2p/net/upgrader"
)

// transport wraps a stock Noise transport behind the dntls.Transport seam.
type transport struct {
	n *noise.Transport
}

var _ dntls.Transport = (*transport)(nil)

// New returns a dntls.Transport backed by the stock Noise transport for the
// given key. See the package comment for the fidelity boundary.
func New(id protocol.ID, key ic.PrivKey, muxers []tptu.StreamMuxer) (dntls.Transport, error) {
	n, err := noise.New(id, key, muxers)
	if err != nil {
		return nil, err
	}
	return &transport{n: n}, nil
}

// SecureInbound runs the Noise handshake as the responder.
func (t *transport) SecureInbound(ctx context.Context, insecure net.Conn, p peer.ID) (sec.SecureConn, error) {
	return t.n.SecureInbound(ctx, insecure, p)
}

// SecureOutbound runs the Noise handshake as the initiator.
func (t *transport) SecureOutbound(ctx context.Context, insecure net.Conn, p peer.ID) (sec.SecureConn, error) {
	return t.n.SecureOutbound(ctx, insecure, p)
}

// ID reports the security protocol ID.
func (t *transport) ID() protocol.ID {
	return t.n.ID()
}

// WithSessionOptions maps seam session parameters onto stock Noise options.
func (t *transport) WithSessionOptions(opts ...dntls.SessionOption) (sec.SecureTransport, error) {
	var params dntls.SessionParams
	for _, opt := range opts {
		if err := opt(&params); err != nil {
			return nil, err
		}
	}
	var nopts []noise.SessionOption
	if params.Prologue != nil {
		nopts = append(nopts, noise.Prologue(params.Prologue))
	}
	if params.DisablePeerIDCheck {
		nopts = append(nopts, noise.DisablePeerIDCheck())
	}
	if params.Initiator != nil || params.Responder != nil {
		nopts = append(nopts, noise.EarlyData(wrapEDH(params.Initiator), wrapEDH(params.Responder)))
	}
	return t.n.WithSessionOptions(nopts...)
}

// edh converts between the seam and Noise early-data handler contracts.
// The NoiseExtensions messages are field-identical; only the Go types differ.
type edh struct {
	h dntls.EarlyDataHandler
}

// wrapEDH wraps a seam handler as a Noise handler, preserving nil.
func wrapEDH(h dntls.EarlyDataHandler) noise.EarlyDataHandler {
	if h == nil {
		return nil
	}
	return edh{h: h}
}

// Send converts the seam extensions to Noise extensions.
func (e edh) Send(ctx context.Context, conn net.Conn, p peer.ID) *noisepb.NoiseExtensions {
	ext := e.h.Send(ctx, conn, p)
	if ext == nil {
		return nil
	}
	return &noisepb.NoiseExtensions{
		WebtransportCerthashes: ext.WebtransportCerthashes,
		StreamMuxers:           ext.StreamMuxers,
	}
}

// Received converts received Noise extensions to seam extensions.
func (e edh) Received(ctx context.Context, conn net.Conn, ext *noisepb.NoiseExtensions) error {
	var converted *dntlspb.NoiseExtensions
	if ext != nil {
		converted = &dntlspb.NoiseExtensions{
			WebtransportCerthashes: ext.WebtransportCerthashes,
			StreamMuxers:           ext.StreamMuxers,
		}
	}
	return e.h.Received(ctx, conn, converted)
}
