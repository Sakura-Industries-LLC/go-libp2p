package dntls

import (
	"bytes"
	"context"
	gocrypto "crypto"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/Sakura-Industries-LLC/ProjectCobra/dntls/lib/core"
	dntlscrypto "github.com/Sakura-Industries-LLC/ProjectCobra/dntls/lib/core/crypto"
	dntlstls "github.com/Sakura-Industries-LLC/ProjectCobra/dntls/lib/tls" //nolint:revive

	ic "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/sec"
	"github.com/libp2p/go-libp2p/p2p/security/dntls/pb"

	"github.com/flynn/noise"
	pool "github.com/libp2p/go-buffer-pool"
	"google.golang.org/protobuf/proto"
)

// payloadSigPrefix is prepended to the Noise static key before signing with
// the DNTLS service key. Same prefix as upstream noise-libp2p for wire
// compatibility of the signature binding.
const payloadSigPrefix = "noise-libp2p-static-key:"

// cipherSuite is shared by all DNTLS-Noise sessions.
var cipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)

func (s *secureSession) runHandshake(ctx context.Context) (err error) {
	defer func() {
		if rerr := recover(); rerr != nil {
			fmt.Fprintf(os.Stderr, "caught panic: %s\n%s\n", rerr, debug.Stack())
			err = fmt.Errorf("panic in DNTLS-Noise handshake: %s", rerr)
		}
	}()

	kp, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		return fmt.Errorf("error generating static keypair: %w", err)
	}

	cfg := noise.Config{
		CipherSuite:   cipherSuite,
		Pattern:       noise.HandshakeXX,
		Initiator:     s.initiator,
		StaticKeypair: kp,
		Prologue:      s.prologue,
	}

	hs, err := noise.NewHandshakeState(cfg)
	if err != nil {
		return fmt.Errorf("error initializing handshake state: %w", err)
	}

	if deadline, ok := ctx.Deadline(); ok {
		if err := s.SetDeadline(deadline); err == nil {
			defer s.SetDeadline(time.Time{})
		}
	}

	hbuf := pool.Get(2 << 10)
	defer pool.Put(hbuf)

	if s.initiator {
		// stage 0: -> e
		if err := s.sendHandshakeMessage(hs, nil, hbuf); err != nil {
			return fmt.Errorf("error sending handshake message: %w", err)
		}

		// stage 1: <- e, ee, s, es, [payload]
		plaintext, err := s.readHandshakeMessage(hs)
		if err != nil {
			return fmt.Errorf("error reading handshake message: %w", err)
		}
		rcvdExt, err := s.handleRemoteHandshakePayload(ctx, plaintext, hs.PeerStatic())
		if err != nil {
			return err
		}
		if s.initiatorEarlyDataHandler != nil {
			if err := s.initiatorEarlyDataHandler.Received(ctx, s.insecureConn, rcvdExt); err != nil {
				return err
			}
		}

		// stage 2: -> s, se, [payload]
		var ext *pb.NoiseExtensions
		if s.initiatorEarlyDataHandler != nil {
			ext = s.initiatorEarlyDataHandler.Send(ctx, s.insecureConn, s.remoteID)
		}
		payload, err := s.generateHandshakePayload(kp, ext)
		if err != nil {
			return err
		}
		if err := s.sendHandshakeMessage(hs, payload, hbuf); err != nil {
			return fmt.Errorf("error sending handshake message: %w", err)
		}
		return nil
	}

	// Responder path.

	// stage 0: <- e
	if _, err := s.readHandshakeMessage(hs); err != nil {
		return fmt.Errorf("error reading handshake message: %w", err)
	}

	// stage 1: -> e, ee, s, es, [payload]
	var ext *pb.NoiseExtensions
	if s.responderEarlyDataHandler != nil {
		ext = s.responderEarlyDataHandler.Send(ctx, s.insecureConn, s.remoteID)
	}
	payload, err := s.generateHandshakePayload(kp, ext)
	if err != nil {
		return err
	}
	if err := s.sendHandshakeMessage(hs, payload, hbuf); err != nil {
		return fmt.Errorf("error sending handshake message: %w", err)
	}

	// stage 2: <- s, se, [payload]
	plaintext, err := s.readHandshakeMessage(hs)
	if err != nil {
		return fmt.Errorf("error reading handshake message: %w", err)
	}
	rcvdExt, err := s.handleRemoteHandshakePayload(ctx, plaintext, hs.PeerStatic())
	if err != nil {
		return err
	}
	if s.responderEarlyDataHandler != nil {
		if err := s.responderEarlyDataHandler.Received(ctx, s.insecureConn, rcvdExt); err != nil {
			return err
		}
	}
	return nil
}

// setCipherStates initializes the cipher states used to protect traffic
// after the handshake completes.
func (s *secureSession) setCipherStates(cs1, cs2 *noise.CipherState) {
	if s.initiator {
		s.enc = cs1
		s.dec = cs2
	} else {
		s.enc = cs2
		s.dec = cs1
	}
}

func (s *secureSession) sendHandshakeMessage(hs *noise.HandshakeState, payload []byte, hbuf []byte) error {
	bz, cs1, cs2, err := hs.WriteMessage(hbuf[:LengthPrefixLength], payload)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bz, uint16(len(bz)-LengthPrefixLength))
	_, err = s.writeMsgInsecure(bz)
	if err != nil {
		return err
	}
	if cs1 != nil && cs2 != nil {
		s.setCipherStates(cs1, cs2)
	}
	return nil
}

func (s *secureSession) readHandshakeMessage(hs *noise.HandshakeState) ([]byte, error) {
	l, err := s.readNextInsecureMsgLen()
	if err != nil {
		return nil, err
	}
	buf := pool.Get(l)
	defer pool.Put(buf)
	if err := s.readNextMsgInsecure(buf); err != nil {
		return nil, err
	}
	msg, cs1, cs2, err := hs.ReadMessage(nil, buf)
	if err != nil {
		return nil, err
	}
	if cs1 != nil && cs2 != nil {
		s.setCipherStates(cs1, cs2)
	}
	return msg, nil
}

// generateHandshakePayload creates a DntlsNoisePayload with DNTLS claims
// and a signature of the Noise static key.
func (s *secureSession) generateHandshakePayload(localStatic noise.DHKey, ext *pb.NoiseExtensions) ([]byte, error) {
	localKeyRaw, err := ic.MarshalPublicKey(s.localPub)
	if err != nil {
		return nil, fmt.Errorf("error serializing libp2p identity key: %w", err)
	}

	// Sign the Noise static key with the DNTLS service key.
	toSign := append([]byte(payloadSigPrefix), localStatic.Public...)
	sig, err := s.serviceKey.Sign(rand.Reader, toSign, gocrypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("error signing handshake payload: %w", err)
	}

	claims := &pb.DntlsClaims{
		OuterHash: s.outerHash,
		Fqdn:      s.fqdn,
	}
	if len(s.subnameHashes) > 0 && s.fqdn == "" {
		claims.SubnameHashes = make([][]byte, len(s.subnameHashes))
		for i, h := range s.subnameHashes {
			claims.SubnameHashes[i] = h[:]
		}
	}

	payloadEnc, err := proto.Marshal(&pb.DntlsNoisePayload{
		IdentityKey: localKeyRaw,
		IdentitySig: sig,
		Claims:      claims,
		Extensions:  ext,
	})
	if err != nil {
		return nil, fmt.Errorf("error marshaling handshake payload: %w", err)
	}
	return payloadEnc, nil
}

// handleRemoteHandshakePayload processes a DntlsNoisePayload from the remote
// peer: verifies the signature, extracts claims, runs three-pillar
// verification, builds PeerIdentity, and calls OnPeerVerified.
func (s *secureSession) handleRemoteHandshakePayload(ctx context.Context, payload []byte, remoteStatic []byte) (*pb.NoiseExtensions, error) {
	var msg pb.DntlsNoisePayload
	if err := proto.Unmarshal(payload, &msg); err != nil {
		return nil, fmt.Errorf("error unmarshaling remote handshake payload: %w", err)
	}

	// Step 1: extract identity_key → ServicePub.
	remotePubKey, err := ic.UnmarshalPublicKey(msg.GetIdentityKey())
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling remote public key: %w", err)
	}

	// Step 2: verify identity_sig against Noise static DH key.
	toVerify := append([]byte(payloadSigPrefix), remoteStatic...)
	ok, err := remotePubKey.Verify(toVerify, msg.GetIdentitySig())
	if err != nil {
		return nil, fmt.Errorf("error verifying signature: %w", err)
	}
	if !ok {
		return nil, fmt.Errorf("handshake signature invalid")
	}

	// Step 3: derive remote peer.ID.
	id, err := peer.IDFromPublicKey(remotePubKey)
	if err != nil {
		return nil, err
	}

	// Step 4: extract claims.
	claims := msg.GetClaims()
	if claims == nil {
		return nil, fmt.Errorf("missing DNTLS claims in handshake payload")
	}
	outerHash := claims.GetOuterHash()
	if len(outerHash) == 0 {
		return nil, fmt.Errorf("missing outer_hash in DNTLS claims")
	}

	// Step 5: determine subname hashes.
	var subnameHashes []core.Subname
	fqdn := claims.GetFqdn()
	var tld core.TLD

	if fqdn != "" {
		tld, _, subnameHashes = parseFQDNClaims(fqdn, s.verifier.Config().CryptoSuite, s.verifier.Config().NetworkID)
	} else if len(claims.GetSubnameHashes()) > 0 {
		subnameHashes = bytesToSubnames(claims.GetSubnameHashes())
	}

	// Step 6: VerifyByOuterHash — full three-pillar verification.
	result, err := s.verifier.VerifyByOuterHash(ctx, core.OuterHash(outerHash), subnameHashes...)
	if err != nil {
		return nil, fmt.Errorf("DNTLS verification failed: %w", err)
	}

	// Verify identity_key matches the on-chain service key. This binds
	// the Noise identity (proven by identity_sig) to the chain registration
	// (proven by VerifyByOuterHash).
	verifiedKey := leafServiceKey(result)
	if verifiedKey != nil {
		remoteRaw, rawErr := remotePubKey.Raw()
		if rawErr != nil {
			return nil, fmt.Errorf("error extracting remote public key bytes: %w", rawErr)
		}
		if !bytes.Equal(remoteRaw, verifiedKey.Bytes()) {
			return nil, fmt.Errorf("identity key does not match verified on-chain service key")
		}
	}

	// FQDN consistency check: if fqdn was disclosed, confirm TLD matches
	// the registration.
	if fqdn != "" && result.Registration != nil {
		if tld != "" && result.Registration.TLD != tld {
			return nil, fmt.Errorf("FQDN TLD mismatch: claimed %q, registration has %q", tld, result.Registration.TLD)
		}
	}

	// Step 7: build PeerIdentity.
	pi := &dntlstls.PeerIdentity{
		OuterHash:    core.OuterHash(outerHash),
		ServiceKey:   verifiedKey,
		Registration: result.Registration,
		VerifyResult: result,
		Verified:     true,
	}
	if fqdn != "" {
		pi.FQDN = core.FQDN(fqdn)
	}

	// Step 8: OnPeerVerified callback.
	if s.onPeerVerified != nil {
		if err := s.onPeerVerified(id, pi); err != nil {
			return nil, fmt.Errorf("OnPeerVerified rejected connection: %w", err)
		}
	}

	// Step 9: check expected peer.ID.
	if s.checkPeerID && s.remoteID != id {
		return nil, sec.ErrPeerIDMismatch{Expected: s.remoteID, Actual: id}
	}

	// Set remote peer state.
	s.remoteID = id
	s.remoteKey = remotePubKey
	s.peerIdentity = pi

	return msg.Extensions, nil
}

// parseFQDNClaims parses a DNTLS FQDN into TLD, label, and derived subname
// hashes. FQDN format: "label.tld" or "child.parent.label.tld" where
// sublabels are ordered child-first (like DNS).
func parseFQDNClaims(fqdn string, suite interface{ Hash(data, salt []byte) []byte }, networkID string) (core.TLD, string, []core.Subname) {
	parts := strings.Split(fqdn, ".")
	if len(parts) < 2 {
		return "", fqdn, nil
	}

	tld := core.TLD(parts[len(parts)-1])
	label := parts[len(parts)-2]

	// Sublabels are everything before label.tld, in child-first order.
	// Reverse to get parent-to-child order for subname hashes.
	sublabels := parts[:len(parts)-2]
	slices.Reverse(sublabels)

	subnameHashes := make([]core.Subname, len(sublabels))
	for i, sub := range sublabels {
		h := suite.Hash([]byte(sub), []byte(networkID))
		copy(subnameHashes[i][:], h)
	}

	return tld, label, subnameHashes
}

func bytesToSubnames(raw [][]byte) []core.Subname {
	out := make([]core.Subname, len(raw))
	for i, b := range raw {
		copy(out[i][:], b)
	}
	return out
}

// leafServiceKey returns the leaf-level service key from a verification
// result. For root identities this is Registration.ServicePub; for subname
// identities it is the last element of Chain.
func leafServiceKey(result *core.Result) dntlscrypto.PublicKey {
	if len(result.Chain) > 0 {
		return result.Chain[len(result.Chain)-1].ServiceKey
	}
	if result.Registration != nil {
		return result.Registration.ServicePub
	}
	return nil
}
