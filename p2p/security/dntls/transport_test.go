package dntls

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Sakura-Industries-LLC/ProjectCobra/dntls/lib/core"
	dntlscrypto "github.com/Sakura-Industries-LLC/ProjectCobra/dntls/lib/core/crypto"
	"github.com/Sakura-Industries-LLC/ProjectCobra/dntls/lib/core/crypto/ed25519sha256"
	dntlstls "github.com/Sakura-Industries-LLC/ProjectCobra/dntls/lib/tls"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/sec"
	"github.com/libp2p/go-libp2p/p2p/security/dntls/pb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Mock verifier
// ---------------------------------------------------------------------------

type mockVerifier struct {
	config  *core.NetworkConfig
	mu      sync.RWMutex
	results map[string]*core.Result // keyed by hex(outerHash)
	errs    map[string]error        // keyed by hex(outerHash)
}

func newMockVerifier() *mockVerifier {
	return &mockVerifier{
		config: &core.NetworkConfig{
			CryptoSuite:      ed25519sha256.New(),
			NetworkID:        "test-network",
			EpochDuration:    24 * time.Hour,
			ExpirationEpochs: 12,
			MaxRecordSize:    65536,
			MaxSubnames:      16,
			MaxDepth:         4,
		},
		results: make(map[string]*core.Result),
		errs:    make(map[string]error),
	}
}

func (v *mockVerifier) register(outerHash []byte, servicePub dntlscrypto.PublicKey) {
	v.mu.Lock()
	defer v.mu.Unlock()
	key := hex.EncodeToString(outerHash)
	v.results[key] = &core.Result{
		Registration: &core.Registration{
			OuterHash:  core.OuterHash(outerHash),
			TLD:        "dntls",
			ServicePub: servicePub,
		},
		FoundOuterHash: core.OuterHash(outerHash),
	}
}

func (v *mockVerifier) registerSubname(outerHash []byte, rootPub, leafPub dntlscrypto.PublicKey) {
	v.mu.Lock()
	defer v.mu.Unlock()
	key := hex.EncodeToString(outerHash)
	v.results[key] = &core.Result{
		Registration: &core.Registration{
			OuterHash:  core.OuterHash(outerHash),
			TLD:        "dntls",
			ServicePub: rootPub,
		},
		FoundOuterHash: core.OuterHash(outerHash),
		Chain: []core.VerifiedRecord{
			{ServiceKey: rootPub},
			{ServiceKey: leafPub},
		},
	}
}

func (v *mockVerifier) reject(outerHash []byte, err error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.errs[hex.EncodeToString(outerHash)] = err
}

func (v *mockVerifier) VerifyByOuterHash(_ context.Context, outerHash core.OuterHash, _ ...core.Subname) (*core.Result, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	key := hex.EncodeToString(outerHash)
	if err, ok := v.errs[key]; ok {
		return nil, err
	}
	if res, ok := v.results[key]; ok {
		return res, nil
	}
	return nil, fmt.Errorf("unknown outer hash: %s", key)
}

func (v *mockVerifier) Verify(context.Context, core.TLD, core.InnerHash, ...core.Subname) (*core.Result, error) {
	panic("not used in dntls-noise tests")
}

func (v *mockVerifier) VerifyWithKey(context.Context, core.TLD, core.InnerHash, dntlscrypto.PublicKey, ...core.Subname) (*core.Result, error) {
	panic("not used in dntls-noise tests")
}

func (v *mockVerifier) VerifyRecord(context.Context, *core.Registration) (*core.VerifiedRecord, error) {
	panic("not used in dntls-noise tests")
}

func (v *mockVerifier) Config() *core.NetworkConfig { return v.config }

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

type testIdentity struct {
	pub       dntlscrypto.PublicKey
	sk        dntlscrypto.SecureKey
	outerHash []byte
}

func genIdentity(t *testing.T) testIdentity {
	t.Helper()
	suite := ed25519sha256.New()
	pub, sk, err := suite.GenerateKeyPair()
	require.NoError(t, err)
	oh := make([]byte, 32)
	copy(oh, pub.Bytes()[:32]) // deterministic, unique per key
	return testIdentity{pub: pub, sk: sk, outerHash: oh}
}

func newTestTransport(t *testing.T, id testIdentity, verifier *mockVerifier) *Transport {
	t.Helper()
	verifier.register(id.outerHash, id.pub)
	tpt, err := New(ID, Config{
		ServiceKey: id.sk,
		OuterHash:  id.outerHash,
		Verifier:   verifier,
	}, nil)
	require.NoError(t, err)
	return tpt
}

func newConnPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	lstnr, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	defer lstnr.Close()

	var client net.Conn
	var clientErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		client, clientErr = net.Dial("tcp", lstnr.Addr().String())
	}()

	server, err := lstnr.Accept()
	<-done
	require.NoError(t, err)
	require.NoError(t, clientErr)
	return client, server
}

func handshake(t *testing.T, init, resp *Transport) (*secureSession, *secureSession) {
	t.Helper()
	c, s := newConnPair(t)

	var initConn sec.SecureConn
	var initErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		initConn, initErr = init.SecureOutbound(context.Background(), c, resp.localID)
	}()

	respConn, respErr := resp.SecureInbound(context.Background(), s, "")
	<-done

	require.NoError(t, initErr)
	require.NoError(t, respErr)
	return initConn.(*secureSession), respConn.(*secureSession)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestConstructorValidation(t *testing.T) {
	suite := ed25519sha256.New()
	_, sk, err := suite.GenerateKeyPair()
	require.NoError(t, err)
	v := newMockVerifier()

	t.Run("nil ServiceKey", func(t *testing.T) {
		_, err := New(ID, Config{Verifier: v, OuterHash: []byte{1}}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ServiceKey")
	})

	t.Run("nil Verifier", func(t *testing.T) {
		_, err := New(ID, Config{ServiceKey: sk, OuterHash: []byte{1}}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Verifier")
	})

	t.Run("empty OuterHash", func(t *testing.T) {
		_, err := New(ID, Config{ServiceKey: sk, Verifier: v}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "OuterHash")
	})
}

func TestDNTLSHandshake(t *testing.T) {
	v := newMockVerifier()
	idA := genIdentity(t)
	idB := genIdentity(t)
	tptA := newTestTransport(t, idA, v)
	tptB := newTestTransport(t, idB, v)

	initConn, respConn := handshake(t, tptA, tptB)
	defer initConn.Close()
	defer respConn.Close()

	// Verify peer IDs.
	assert.Equal(t, tptB.localID, initConn.RemotePeer())
	assert.Equal(t, tptA.localID, respConn.RemotePeer())

	// Verify PeerIdentity is populated.
	require.NotNil(t, initConn.PeerIdentity())
	assert.True(t, initConn.PeerIdentity().Verified)
	assert.Equal(t, core.OuterHash(idB.outerHash), initConn.PeerIdentity().OuterHash)

	require.NotNil(t, respConn.PeerIdentity())
	assert.True(t, respConn.PeerIdentity().Verified)
	assert.Equal(t, core.OuterHash(idA.outerHash), respConn.PeerIdentity().OuterHash)

	// Verify encrypted data exchange.
	msg := []byte("hello dntls")
	_, err := initConn.Write(msg)
	require.NoError(t, err)

	buf := make([]byte, len(msg))
	_, err = io.ReadFull(respConn, buf)
	require.NoError(t, err)
	assert.Equal(t, msg, buf)
}

func TestRootIdentityNoSubnames(t *testing.T) {
	v := newMockVerifier()
	id := genIdentity(t)
	tptA := newTestTransport(t, id, v)

	idB := genIdentity(t)
	tptB := newTestTransport(t, idB, v)

	initConn, _ := handshake(t, tptA, tptB)
	defer initConn.Close()

	pi := initConn.PeerIdentity()
	require.NotNil(t, pi)
	assert.True(t, pi.Verified)
	assert.Empty(t, pi.FQDN)
}

func TestSubnameWithFQDN(t *testing.T) {
	v := newMockVerifier()
	suite := ed25519sha256.New()

	// Create root key and leaf key.
	rootPub, _, err := suite.GenerateKeyPair()
	require.NoError(t, err)
	leafPub, leafSK, err := suite.GenerateKeyPair()
	require.NoError(t, err)

	outerHash := make([]byte, 32)
	copy(outerHash, leafPub.Bytes()[:32])

	// Register as subname identity.
	v.registerSubname(outerHash, rootPub, leafPub)

	tptA, err := New(ID, Config{
		ServiceKey: leafSK,
		OuterHash:  outerHash,
		FQDN:       "sub.alice.dntls",
		Verifier:   v,
	}, nil)
	require.NoError(t, err)

	idB := genIdentity(t)
	tptB := newTestTransport(t, idB, v)

	_, respConn := handshake(t, tptA, tptB)
	defer respConn.Close()

	pi := respConn.PeerIdentity()
	require.NotNil(t, pi)
	assert.True(t, pi.Verified)
	assert.Equal(t, core.FQDN("sub.alice.dntls"), pi.FQDN)
}

func TestSubnameWithoutFQDN(t *testing.T) {
	v := newMockVerifier()
	suite := ed25519sha256.New()

	rootPub, _, err := suite.GenerateKeyPair()
	require.NoError(t, err)
	leafPub, leafSK, err := suite.GenerateKeyPair()
	require.NoError(t, err)

	outerHash := make([]byte, 32)
	copy(outerHash, leafPub.Bytes()[:32])

	v.registerSubname(outerHash, rootPub, leafPub)

	subnameHash := core.Subname{}
	copy(subnameHash[:], suite.Hash([]byte("sub"), []byte("test-network")))

	tptA, err := New(ID, Config{
		ServiceKey:    leafSK,
		OuterHash:     outerHash,
		SubnameHashes: []core.Subname{subnameHash},
		Verifier:      v,
	}, nil)
	require.NoError(t, err)

	idB := genIdentity(t)
	tptB := newTestTransport(t, idB, v)

	_, respConn := handshake(t, tptA, tptB)
	defer respConn.Close()

	pi := respConn.PeerIdentity()
	require.NotNil(t, pi)
	assert.True(t, pi.Verified)
	assert.Empty(t, pi.FQDN) // no FQDN disclosed
}

func TestVerificationFailure(t *testing.T) {
	v := newMockVerifier()
	idA := genIdentity(t)
	idB := genIdentity(t)

	// Register B normally, but make A's outer hash fail verification.
	v.register(idB.outerHash, idB.pub)
	v.reject(idA.outerHash, errors.New("verification rejected"))

	tptA, err := New(ID, Config{
		ServiceKey: idA.sk,
		OuterHash:  idA.outerHash,
		Verifier:   v,
	}, nil)
	require.NoError(t, err)
	tptB := newTestTransport(t, idB, v)

	c, s := newConnPair(t)

	var initErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, initErr = tptA.SecureOutbound(context.Background(), c, tptB.localID)
	}()

	_, respErr := tptB.SecureInbound(context.Background(), s, "")
	<-done

	// The responder should fail because A's claims fail verification.
	// The initiator may also fail depending on which side errors first.
	assert.True(t, respErr != nil || initErr != nil, "at least one side should fail")
}

func TestWrongPeerID(t *testing.T) {
	v := newMockVerifier()
	idA := genIdentity(t)
	idB := genIdentity(t)
	tptA := newTestTransport(t, idA, v)
	tptB := newTestTransport(t, idB, v)

	c, s := newConnPair(t)

	var initErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		// Dial with a wrong peer ID.
		_, initErr = tptA.SecureOutbound(context.Background(), c, "QmWrongPeerID")
	}()

	_, _ = tptB.SecureInbound(context.Background(), s, "")
	<-done

	require.Error(t, initErr)
	var mismatch sec.ErrPeerIDMismatch
	assert.True(t, errors.As(initErr, &mismatch))
}

func TestKeyRotation(t *testing.T) {
	v := newMockVerifier()

	// Same outer hash, new service key (simulates key rotation).
	suite := ed25519sha256.New()
	_, oldSK, err := suite.GenerateKeyPair()
	require.NoError(t, err)
	newPub, newSK, err := suite.GenerateKeyPair()
	require.NoError(t, err)
	_ = oldSK // old key is retired

	outerHash := make([]byte, 32)
	copy(outerHash, newPub.Bytes()[:32])
	v.register(outerHash, newPub)

	tptA, err := New(ID, Config{
		ServiceKey: newSK,
		OuterHash:  outerHash,
		Verifier:   v,
	}, nil)
	require.NoError(t, err)

	idB := genIdentity(t)
	tptB := newTestTransport(t, idB, v)

	initConn, _ := handshake(t, tptA, tptB)
	defer initConn.Close()

	// The new key produces a new peer.ID but verification still passes.
	newLibp2pPub, err := dntlsPubToLibp2p(newPub, dntlscrypto.SigEd25519)
	require.NoError(t, err)
	expectedID, err := peer.IDFromPublicKey(newLibp2pPub)
	require.NoError(t, err)
	assert.Equal(t, expectedID, tptA.localID)
}

func TestOnPeerVerifiedError(t *testing.T) {
	v := newMockVerifier()
	idA := genIdentity(t)
	idB := genIdentity(t)
	v.register(idA.outerHash, idA.pub)
	v.register(idB.outerHash, idB.pub)

	tptA, err := New(ID, Config{
		ServiceKey: idA.sk,
		OuterHash:  idA.outerHash,
		Verifier:   v,
	}, nil)
	require.NoError(t, err)

	// B's transport rejects all peers via OnPeerVerified.
	tptB, err := New(ID, Config{
		ServiceKey:     idB.sk,
		OuterHash:      idB.outerHash,
		Verifier:       v,
		OnPeerVerified: func(peer.ID, *dntlstls.PeerIdentity) error { return errors.New("rejected by policy") },
	}, nil)
	require.NoError(t, err)

	c, s := newConnPair(t)

	var initErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, initErr = tptA.SecureOutbound(context.Background(), c, tptB.localID)
	}()

	_, respErr := tptB.SecureInbound(context.Background(), s, "")
	<-done

	// B's side rejects because OnPeerVerified returns an error.
	assert.True(t, respErr != nil || initErr != nil, "at least one side should fail")
	if respErr != nil {
		assert.Contains(t, respErr.Error(), "rejected by policy")
	}
}

func TestEarlyDataMuxerNegotiation(t *testing.T) {
	v := newMockVerifier()
	idA := genIdentity(t)
	idB := genIdentity(t)

	tptA := newTestTransport(t, idA, v)
	tptB := newTestTransport(t, idB, v)

	// Set up custom early data handlers for cert hash exchange.
	var receivedByInit, receivedByResp *pb.NoiseExtensions

	initEDH := &testEarlyDataHandler{
		sendExt: &pb.NoiseExtensions{WebtransportCerthashes: [][]byte{{1, 2, 3}}},
		onRecv:  func(ext *pb.NoiseExtensions) { receivedByInit = ext },
	}
	respEDH := &testEarlyDataHandler{
		sendExt: &pb.NoiseExtensions{WebtransportCerthashes: [][]byte{{4, 5, 6}}},
		onRecv:  func(ext *pb.NoiseExtensions) { receivedByResp = ext },
	}

	initST, err := tptA.WithSessionOptions(EarlyData(initEDH, nil))
	require.NoError(t, err)
	respST, err := tptB.WithSessionOptions(EarlyData(nil, respEDH))
	require.NoError(t, err)

	c, s := newConnPair(t)

	var initConn sec.SecureConn
	done := make(chan struct{})
	go func() {
		defer close(done)
		initConn, err = initST.SecureOutbound(context.Background(), c, tptB.localID)
	}()

	_, respErr := respST.SecureInbound(context.Background(), s, "")
	<-done

	require.NoError(t, err)
	require.NoError(t, respErr)
	defer initConn.Close()

	// Verify early data was exchanged.
	require.NotNil(t, receivedByInit, "initiator should receive responder's early data")
	assert.Equal(t, [][]byte{{4, 5, 6}}, receivedByInit.WebtransportCerthashes)

	require.NotNil(t, receivedByResp, "responder should receive initiator's early data")
	assert.Equal(t, [][]byte{{1, 2, 3}}, receivedByResp.WebtransportCerthashes)
}

func TestPrologueMatch(t *testing.T) {
	v := newMockVerifier()
	idA := genIdentity(t)
	idB := genIdentity(t)
	tptA := newTestTransport(t, idA, v)
	tptB := newTestTransport(t, idB, v)

	prologue := []byte("test-prologue")

	stA, err := tptA.WithSessionOptions(Prologue(prologue))
	require.NoError(t, err)
	stB, err := tptB.WithSessionOptions(Prologue(prologue))
	require.NoError(t, err)

	c, s := newConnPair(t)

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := stA.SecureOutbound(context.Background(), c, tptB.localID)
		require.NoError(t, err)
		conn.Close()
	}()

	conn, err := stB.SecureInbound(context.Background(), s, "")
	require.NoError(t, err)
	conn.Close()
	<-done
}

func TestPrologueMismatch(t *testing.T) {
	v := newMockVerifier()
	idA := genIdentity(t)
	idB := genIdentity(t)
	tptA := newTestTransport(t, idA, v)
	tptB := newTestTransport(t, idB, v)

	stA, err := tptA.WithSessionOptions(Prologue([]byte("prologue-A")))
	require.NoError(t, err)
	stB, err := tptB.WithSessionOptions(Prologue([]byte("prologue-B")))
	require.NoError(t, err)

	c, s := newConnPair(t)

	var initErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, initErr = stA.SecureOutbound(context.Background(), c, tptB.localID)
	}()

	_, respErr := stB.SecureInbound(context.Background(), s, "")
	<-done

	assert.True(t, initErr != nil || respErr != nil, "mismatched prologue must fail")
}

func TestVanillaLibp2pIncompatibility(t *testing.T) {
	// DNTLS-Noise uses protocol ID "/dntls/1.0.0", not "/noise".
	// Protocol negotiation would fail at the multistream level for any
	// vanilla libp2p peer expecting "/noise".
	v := newMockVerifier()
	id := genIdentity(t)
	tpt := newTestTransport(t, id, v)
	assert.Equal(t, ID, string(tpt.ID()))
	assert.NotEqual(t, "/noise", string(tpt.ID()))
}

func TestLargePayload(t *testing.T) {
	v := newMockVerifier()
	idA := genIdentity(t)
	idB := genIdentity(t)
	tptA := newTestTransport(t, idA, v)
	tptB := newTestTransport(t, idB, v)

	initConn, respConn := handshake(t, tptA, tptB)
	defer initConn.Close()
	defer respConn.Close()

	// Send a payload larger than MaxPlaintextLength to test chunking.
	data := bytes.Repeat([]byte{0xAB}, MaxPlaintextLength+1000)
	_, err := initConn.Write(data)
	require.NoError(t, err)

	buf := make([]byte, len(data))
	_, err = io.ReadFull(respConn, buf)
	require.NoError(t, err)
	assert.Equal(t, data, buf)
}

func TestPeerIdentityExtractor(t *testing.T) {
	v := newMockVerifier()
	idA := genIdentity(t)
	idB := genIdentity(t)
	tptA := newTestTransport(t, idA, v)
	tptB := newTestTransport(t, idB, v)

	initConn, _ := handshake(t, tptA, tptB)
	defer initConn.Close()

	// Package-level PeerIdentity extractor.
	pi := PeerIdentity(initConn)
	require.NotNil(t, pi)
	assert.True(t, pi.Verified)

	// Non-DNTLS connection returns nil.
	pi = PeerIdentity(nil)
	assert.Nil(t, pi)
}

// ---------------------------------------------------------------------------
// Test early data handler
// ---------------------------------------------------------------------------

type testEarlyDataHandler struct {
	sendExt *pb.NoiseExtensions
	onRecv  func(*pb.NoiseExtensions)
}

func (h *testEarlyDataHandler) Send(context.Context, net.Conn, peer.ID) *pb.NoiseExtensions {
	return h.sendExt
}

func (h *testEarlyDataHandler) Received(_ context.Context, _ net.Conn, ext *pb.NoiseExtensions) error {
	if h.onRecv != nil {
		h.onRecv(ext)
	}
	return nil
}
