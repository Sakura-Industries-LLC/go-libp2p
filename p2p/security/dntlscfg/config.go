package dntlscfg

import (
	"crypto/tls"

	ic "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

// PeerIdentityExtractor extracts a libp2p public key and peer ID from
// a completed TLS connection. Replaces p2ptls.PubKeyFromCertChain for
// DNTLS connections where identity is carried in URI SANs.
type PeerIdentityExtractor func(state tls.ConnectionState) (ic.PubKey, peer.ID, error)

// Provider supplies TLS configurations for DNTLS-secured transports.
// The lib/tls.Handshaker satisfies this interface via a thin adapter
// in the appnet transport modules.
type Provider interface {
	ClientTLSConfig(expectedPeer peer.ID) (*tls.Config, error)
	ServerTLSConfig() (*tls.Config, error)
	ExtractPeerIdentity(state tls.ConnectionState) (ic.PubKey, peer.ID, error)
}
