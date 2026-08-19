package libp2pquic

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"testing"

	ic "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/security/dntlscfg"

	"github.com/stretchr/testify/require"
)

// TestDNTLSProviderHandshake exercises the WithDNTLSProvider code paths:
// client TLS config, server TLS config, and identity extraction on both the
// dial and accept sides. The stock provider reproduces upstream TLS
// semantics, so peer identities must match exactly as in TestHandshake.
func TestDNTLSProviderHandshake(t *testing.T) {
	serverID, serverKey := createPeer(t)
	clientID, clientKey := createPeer(t)

	serverProvider, err := dntlscfg.NewStockTLSProvider(serverKey)
	require.NoError(t, err)
	clientProvider, err := dntlscfg.NewStockTLSProvider(clientKey)
	require.NoError(t, err)

	serverTransport, err := NewTransport(serverKey, newConnManager(t), nil, nil, nil, WithDNTLSProvider(serverProvider))
	require.NoError(t, err)
	defer serverTransport.(io.Closer).Close()

	clientTransport, err := NewTransport(clientKey, newConnManager(t), nil, nil, nil, WithDNTLSProvider(clientProvider))
	require.NoError(t, err)
	defer clientTransport.(io.Closer).Close()

	ln := runServer(t, serverTransport, "/ip4/127.0.0.1/udp/0/quic-v1")
	defer ln.Close()

	conn, err := clientTransport.Dial(context.Background(), ln.Multiaddr(), serverID)
	require.NoError(t, err)
	defer conn.Close()
	serverConn, err := ln.Accept()
	require.NoError(t, err)
	defer serverConn.Close()

	require.Equal(t, clientID, conn.LocalPeer())
	require.Equal(t, serverID, conn.RemotePeer())
	require.True(t, conn.RemotePublicKey().Equals(serverKey.GetPublic()), "remote public key doesn't match")

	require.Equal(t, serverID, serverConn.LocalPeer())
	require.Equal(t, clientID, serverConn.RemotePeer())
	require.True(t, serverConn.RemotePublicKey().Equals(clientKey.GetPublic()), "remote public key doesn't match")
}

// TestDNTLSProviderRejectsFailedExtraction pins that a provider error on
// identity extraction fails the dial instead of falling back to the stock
// path.
func TestDNTLSProviderRejectsFailedExtraction(t *testing.T) {
	serverID, serverKey := createPeer(t)
	_, clientKey := createPeer(t)

	serverProvider, err := dntlscfg.NewStockTLSProvider(serverKey)
	require.NoError(t, err)
	clientProvider, err := dntlscfg.NewStockTLSProvider(clientKey)
	require.NoError(t, err)

	serverTransport, err := NewTransport(serverKey, newConnManager(t), nil, nil, nil, WithDNTLSProvider(serverProvider))
	require.NoError(t, err)
	defer serverTransport.(io.Closer).Close()

	clientTransport, err := NewTransport(clientKey, newConnManager(t), nil, nil, nil, WithDNTLSProvider(failingExtraction{clientProvider}))
	require.NoError(t, err)
	defer clientTransport.(io.Closer).Close()

	ln := runServer(t, serverTransport, "/ip4/127.0.0.1/udp/0/quic-v1")
	defer ln.Close()

	_, err = clientTransport.Dial(context.Background(), ln.Multiaddr(), serverID)
	require.ErrorContains(t, err, "DNTLS identity extraction")
}

// failingExtraction wraps a provider and fails every identity extraction.
type failingExtraction struct {
	dntlscfg.Provider
}

// ExtractPeerIdentity always fails.
func (failingExtraction) ExtractPeerIdentity(tls.ConnectionState) (ic.PubKey, peer.ID, error) {
	return nil, "", errors.New("extraction refused")
}
