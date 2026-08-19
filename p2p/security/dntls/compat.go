package dntls

import (
	"fmt"

	dntlscrypto "github.com/Sakura-Industries-LLC/ProjectCobra/dntls/lib/core/crypto"

	ic "github.com/libp2p/go-libp2p/core/crypto"
)

// dntlsPubToLibp2p converts a DNTLS public key to a libp2p public key.
// The conversion depends on the key's signature algorithm.
func dntlsPubToLibp2p(pub dntlscrypto.PublicKey, alg dntlscrypto.SignatureAlg) (ic.PubKey, error) {
	raw := pub.Bytes()
	switch alg {
	case dntlscrypto.SigEd25519:
		return ic.UnmarshalEd25519PublicKey(raw)
	case dntlscrypto.SigSecp256k1:
		return ic.UnmarshalSecp256k1PublicKey(raw)
	default:
		return nil, fmt.Errorf("dntls: unsupported signature algorithm %d for libp2p key conversion", alg)
	}
}
