package libp2pquic

import (
	"crypto/tls"
	"testing"

	ic "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/security/dntlscfg"
	p2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"
)

// testProvider wraps p2ptls.Identity to implement dntlscfg.Provider for tests.
type testProvider struct {
	identity *p2ptls.Identity
}

var _ dntlscfg.Provider = (*testProvider)(nil)

func newTestProvider(t testing.TB, key ic.PrivKey) dntlscfg.Provider {
	t.Helper()
	identity, err := p2ptls.NewIdentity(key)
	if err != nil {
		t.Fatal(err)
	}
	return &testProvider{identity: identity}
}

func (p *testProvider) ClientTLSConfig(expectedPeer peer.ID) (*tls.Config, error) {
	conf, _ := p.identity.ConfigForPeer(expectedPeer)
	return conf, nil
}

func (p *testProvider) ServerTLSConfig() (*tls.Config, error) {
	conf, _ := p.identity.ConfigForPeer("")
	return conf, nil
}

func (p *testProvider) ExtractPeerIdentity(state tls.ConnectionState) (ic.PubKey, peer.ID, error) {
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
