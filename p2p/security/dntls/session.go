package dntls

import (
	"bufio"
	"context"
	"net"
	"sync"
	"time"

	"github.com/flynn/noise"

	"github.com/Sakura-Industries-LLC/ProjectCobra/dntls/lib/core"
	dntlscrypto "github.com/Sakura-Industries-LLC/ProjectCobra/dntls/lib/core/crypto"
	dntlstls "github.com/Sakura-Industries-LLC/ProjectCobra/dntls/lib/tls"

	ic "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
)

type secureSession struct {
	initiator   bool
	checkPeerID bool

	localID  peer.ID
	localPub ic.PubKey // ServicePub as libp2p PubKey (for marshaling)
	remoteID peer.ID
	// remoteKey is the remote peer's libp2p public key, set during handshake.
	remoteKey ic.PubKey

	// DNTLS identity fields, copied from the Transport's Config.
	serviceKey     dntlscrypto.SecureKey
	sigAlg         dntlscrypto.SignatureAlg
	verifier       Verifier
	outerHash      []byte
	fqdn           string
	subnameHashes  []core.Subname
	onPeerVerified func(peer.ID, *dntlstls.PeerIdentity) error

	// peerIdentity is populated after a successful handshake.
	peerIdentity *dntlstls.PeerIdentity

	readLock  sync.Mutex
	writeLock sync.Mutex

	insecureConn   net.Conn
	insecureReader *bufio.Reader

	qseek int
	qbuf  []byte
	rlen  [2]byte

	enc *noise.CipherState
	dec *noise.CipherState

	prologue []byte

	initiatorEarlyDataHandler, responderEarlyDataHandler EarlyDataHandler

	connectionState network.ConnectionState
}

func newSecureSession(tpt *Transport, ctx context.Context, insecure net.Conn, remote peer.ID, prologue []byte, initiatorEDH, responderEDH EarlyDataHandler, initiator, checkPeerID bool) (*secureSession, error) {
	s := &secureSession{
		insecureConn:              insecure,
		insecureReader:            bufio.NewReader(insecure),
		initiator:                 initiator,
		localID:                   tpt.localID,
		localPub:                  tpt.localPub,
		serviceKey:                tpt.cfg.ServiceKey,
		sigAlg:                    tpt.sigAlg,
		verifier:                  tpt.cfg.Verifier,
		outerHash:                 tpt.cfg.OuterHash,
		fqdn:                      tpt.cfg.FQDN,
		subnameHashes:             tpt.cfg.SubnameHashes,
		onPeerVerified:            tpt.cfg.OnPeerVerified,
		remoteID:                  remote,
		prologue:                  prologue,
		initiatorEarlyDataHandler: initiatorEDH,
		responderEarlyDataHandler: responderEDH,
		checkPeerID:               checkPeerID,
	}

	respCh := make(chan error, 1)
	go func() {
		respCh <- s.runHandshake(ctx)
	}()

	select {
	case err := <-respCh:
		if err != nil {
			_ = s.insecureConn.Close()
		}
		return s, err
	case <-ctx.Done():
		_ = s.insecureConn.Close()
		<-respCh
		return nil, ctx.Err()
	}
}

func (s *secureSession) LocalAddr() net.Addr        { return s.insecureConn.LocalAddr() }
func (s *secureSession) LocalPeer() peer.ID         { return s.localID }
func (s *secureSession) LocalPublicKey() ic.PubKey  { return s.localPub }
func (s *secureSession) RemoteAddr() net.Addr       { return s.insecureConn.RemoteAddr() }
func (s *secureSession) RemotePeer() peer.ID        { return s.remoteID }
func (s *secureSession) RemotePublicKey() ic.PubKey { return s.remoteKey }

func (s *secureSession) PeerIdentity() *dntlstls.PeerIdentity { return s.peerIdentity }

func (s *secureSession) ConnState() network.ConnectionState { return s.connectionState }

func (s *secureSession) SetDeadline(t time.Time) error     { return s.insecureConn.SetDeadline(t) }
func (s *secureSession) SetReadDeadline(t time.Time) error { return s.insecureConn.SetReadDeadline(t) }
func (s *secureSession) SetWriteDeadline(t time.Time) error {
	return s.insecureConn.SetWriteDeadline(t)
}
func (s *secureSession) Close() error { return s.insecureConn.Close() }

// SessionWithConnState sets the connection state on a completed session.
func SessionWithConnState(s *secureSession, muxer protocol.ID) *secureSession {
	if s != nil {
		s.connectionState.StreamMultiplexer = muxer
		s.connectionState.UsedEarlyMuxerNegotiation = muxer != ""
	}
	return s
}
