package libp2pquic

import (
	"github.com/libp2p/go-libp2p/p2p/security/dntlscfg"
	p2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"
)

// Option is a function that configures the QUIC transport.
type Option func(o *transportConfig) error

type transportConfig struct {
	tlsIdentityOpts []p2ptls.IdentityOption
	dntlsProvider   dntlscfg.Provider
}

// WithTLSIdentityOption passes the given p2ptls.IdentityOption through to the
// TLS identity used by the QUIC transport.
func WithTLSIdentityOption(opt ...p2ptls.IdentityOption) Option {
	return func(c *transportConfig) error {
		c.tlsIdentityOpts = append(c.tlsIdentityOpts, opt...)
		return nil
	}
}

// WithDNTLSProvider sources the transport's TLS configuration and peer
// identity extraction from the given DNTLS provider instead of the stock
// libp2p TLS identity. tlsIdentityOpts are ignored when a provider is set.
func WithDNTLSProvider(provider dntlscfg.Provider) Option {
	return func(c *transportConfig) error {
		c.dntlsProvider = provider
		return nil
	}
}
