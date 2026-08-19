package dntlscfg

import (
	"crypto/tls"

	ic "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	p2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"
)

// stockProvider implements Provider using the stock libp2p TLS identity.
type stockProvider struct {
	identity *p2ptls.Identity
}

var _ Provider = (*stockProvider)(nil)

// NewStockTLSProvider returns a Provider backed by the stock libp2p TLS
// identity for the given key. It provides no DNTLS verification: peers
// authenticate exactly as with upstream go-libp2p TLS. Intended for tests
// and tooling that need a working QUIC transport without a DNTLS stack;
// production DNTLS hosts must inject the SDK's provider instead.
func NewStockTLSProvider(key ic.PrivKey) (Provider, error) {
	identity, err := p2ptls.NewIdentity(key)
	if err != nil {
		return nil, err
	}
	return &stockProvider{identity: identity}, nil
}

// ClientTLSConfig returns a TLS config expecting the given peer.
func (p *stockProvider) ClientTLSConfig(expectedPeer peer.ID) (*tls.Config, error) {
	conf, _ := p.identity.ConfigForPeer(expectedPeer)
	return conf, nil
}

// ServerTLSConfig returns a TLS config for inbound connections.
func (p *stockProvider) ServerTLSConfig() (*tls.Config, error) {
	conf, _ := p.identity.ConfigForPeer("")
	return conf, nil
}

// ExtractPeerIdentity recovers the peer identity from the certificate chain.
func (p *stockProvider) ExtractPeerIdentity(state tls.ConnectionState) (ic.PubKey, peer.ID, error) {
	pubKey, err := p2ptls.PubKeyFromCertChain(state.PeerCertificates)
	if err != nil {
		return nil, "", err
	}
	peerID, err := peer.IDFromPublicKey(pubKey)
	if err != nil {
		return nil, "", err
	}
	return pubKey, peerID, nil
}
