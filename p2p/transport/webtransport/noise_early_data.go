package libp2pwebtransport

import (
	"context"
	"net"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/security/dntls"
	"github.com/libp2p/go-libp2p/p2p/security/dntls/pb"
)

type earlyDataHandler struct {
	earlyData *pb.NoiseExtensions
	receive   func(extensions *pb.NoiseExtensions) error
}

var _ dntls.EarlyDataHandler = &earlyDataHandler{}

func newEarlyDataSender(earlyData *pb.NoiseExtensions) dntls.EarlyDataHandler {
	return &earlyDataHandler{earlyData: earlyData}
}

func newEarlyDataReceiver(receive func(*pb.NoiseExtensions) error) dntls.EarlyDataHandler {
	return &earlyDataHandler{receive: receive}
}

func (e *earlyDataHandler) Send(context.Context, net.Conn, peer.ID) *pb.NoiseExtensions {
	return e.earlyData
}

func (e *earlyDataHandler) Received(_ context.Context, _ net.Conn, ext *pb.NoiseExtensions) error {
	if e.receive == nil {
		return nil
	}
	return e.receive(ext)
}
