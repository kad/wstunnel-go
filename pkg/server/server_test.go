package server

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kad/wstunnel-go/pkg/protocol"
	"gopkg.in/yaml.v3"
)

func signedToken(t *testing.T, secret string) string {
	t.Helper()

	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, protocol.JwtTunnelConfig{
		ID:     "token-id",
		Remote: "example.com",
		Port:   443,
		Protocol: protocol.LocalProtocol{
			Tcp: &protocol.TcpProtocol{},
		},
	}).SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}

	return token
}

func unsignedToken(t *testing.T) string {
	t.Helper()

	token, err := jwt.NewWithClaims(jwt.SigningMethodNone, protocol.JwtTunnelConfig{
		ID:     "token-id",
		Remote: "example.com",
		Port:   443,
		Protocol: protocol.LocalProtocol{
			Tcp: &protocol.TcpProtocol{},
		},
	}).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("SignedString() error = %v", err)
	}

	return token
}

func unsupportedAlgToken() string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"unsupported","typ":"JWT"}`))
	payload, err := json.Marshal(protocol.JwtTunnelConfig{
		ID:     "token-id",
		Remote: "example.com",
		Port:   443,
		Protocol: protocol.LocalProtocol{
			Tcp: &protocol.TcpProtocol{},
		},
	})
	if err != nil {
		panic(err)
	}
	claims := base64.RawURLEncoding.EncodeToString(payload)
	return header + "." + claims + ".signature"
}

func TestConfigYAMLUsesHTTPUpgradePathPrefix(t *testing.T) {
	var cfg Config
	if err := yaml.Unmarshal([]byte("http_upgrade_path_prefix: api\n"), &cfg); err != nil {
		t.Fatalf("yaml.Unmarshal() error = %v", err)
	}

	if cfg.PathPrefix != "api" {
		t.Fatalf("PathPrefix = %q, want %q", cfg.PathPrefix, "api")
	}
}

func TestConfigYAMLAcceptsLegacyRestrictHTTPUpgradePathPrefix(t *testing.T) {
	var cfg Config
	if err := yaml.Unmarshal([]byte("restrict_http_upgrade_path_prefix: legacy\n"), &cfg); err != nil {
		t.Fatalf("yaml.Unmarshal() error = %v", err)
	}

	if cfg.PathPrefix != "legacy" {
		t.Fatalf("PathPrefix = %q, want %q", cfg.PathPrefix, "legacy")
	}
}

func TestParseJWTClaimsWithSharedSecret(t *testing.T) {
	srv := NewServer(Config{
		WebsocketProtocol: "ws",
		JWTSecret:         "shared-secret",
	})

	claims, err := srv.parseJWTClaims(signedToken(t, "shared-secret"))
	if err != nil {
		t.Fatalf("parseJWTClaims() error = %v", err)
	}
	if claims.Remote != "example.com" || claims.Port != 443 {
		t.Fatalf("parseJWTClaims() got %+v", claims)
	}
}

func TestParseJWTClaimsRejectsWrongSecret(t *testing.T) {
	srv := NewServer(Config{
		WebsocketProtocol: "ws",
		JWTSecret:         "shared-secret",
	})

	if _, err := srv.parseJWTClaims(signedToken(t, "other-secret")); err == nil {
		t.Fatal("parseJWTClaims() unexpectedly accepted token signed with another secret")
	}
}

func TestParseJWTClaimsRustModeIgnoresVerificationSecret(t *testing.T) {
	srv := NewServer(Config{
		WebsocketProtocol: "rust",
		JWTSecret:         "shared-secret",
	})

	claims, err := srv.parseJWTClaims(signedToken(t, "other-secret"))
	if err != nil {
		t.Fatalf("parseJWTClaims() error = %v", err)
	}
	if claims.Remote != "example.com" || claims.Port != 443 {
		t.Fatalf("parseJWTClaims() got %+v", claims)
	}
}

func TestParseJWTClaimsCompatibilityModeRejectsUnsignedToken(t *testing.T) {
	srv := NewServer(Config{
		WebsocketProtocol:       "ws",
		InsecureNoJWTValidation: true,
	})

	if _, err := srv.parseJWTClaims(unsignedToken(t)); err == nil {
		t.Fatal("parseJWTClaims() unexpectedly accepted unsigned token")
	}
}

func TestParseJWTClaimsCompatibilityModeAcceptsHS256Shape(t *testing.T) {
	srv := NewServer(Config{
		WebsocketProtocol:       "ws",
		InsecureNoJWTValidation: true,
	})

	claims, err := srv.parseJWTClaims(signedToken(t, "other-secret"))
	if err != nil {
		t.Fatalf("parseJWTClaims() error = %v", err)
	}
	if claims.Remote != "example.com" || claims.Port != 443 {
		t.Fatalf("parseJWTClaims() got %+v", claims)
	}
}

func TestParseJWTClaimsRejectsUnsupportedAlgorithmWithoutPanicking(t *testing.T) {
	t.Run("unverified", func(t *testing.T) {
		srv := NewServer(Config{WebsocketProtocol: "rust"})

		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("parseJWTClaims() panicked: %v", r)
			}
		}()

		if _, err := srv.parseJWTClaims(unsupportedAlgToken()); err == nil {
			t.Fatal("parseJWTClaims() unexpectedly accepted unsupported algorithm")
		}
	})

	t.Run("verified", func(t *testing.T) {
		srv := NewServer(Config{
			WebsocketProtocol: "ws",
			JWTSecret:         "shared-secret",
		})

		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("parseJWTClaims() panicked: %v", r)
			}
		}()

		if _, err := srv.parseJWTClaims(unsupportedAlgToken()); err == nil {
			t.Fatal("parseJWTClaims() unexpectedly accepted unsupported algorithm")
		}
	})
}

type nopReadWriteCloser struct {
	closed chan struct{}
}

func (n *nopReadWriteCloser) Read(_ []byte) (int, error) {
	<-n.closed
	return 0, io.EOF
}

func (n *nopReadWriteCloser) Write(p []byte) (int, error) {
	return len(p), nil
}

func (n *nopReadWriteCloser) Close() error {
	select {
	case <-n.closed:
	default:
		close(n.closed)
	}
	return nil
}

type blockingReadWriteCloser struct {
	readStarted chan struct{}
	release     chan struct{}
	closed      chan struct{}
	once        sync.Once
}

func (b *blockingReadWriteCloser) Read(_ []byte) (int, error) {
	b.once.Do(func() {
		close(b.readStarted)
	})

	select {
	case <-b.release:
	case <-b.closed:
	}
	return 0, io.EOF
}

func (b *blockingReadWriteCloser) Write(p []byte) (int, error) {
	return len(p), nil
}

func (b *blockingReadWriteCloser) Close() error {
	select {
	case <-b.closed:
	default:
		close(b.closed)
	}
	select {
	case <-b.release:
	default:
		close(b.release)
	}
	return nil
}

func TestReverseTunnelManagerReapsIdleListener(t *testing.T) {
	mgr := NewReverseTunnelManager(0, 50*time.Millisecond)
	t.Cleanup(mgr.Close)
	claims := &protocol.JwtTunnelConfig{
		ID:     "reverse-idle",
		Remote: "127.0.0.1",
		Port:   0,
		Protocol: protocol.LocalProtocol{
			ReverseTcp: &struct{}{},
		},
	}

	tl, _, err := mgr.getOrCreateListener(claims)
	if err != nil {
		t.Fatalf("getOrCreateListener() error = %v", err)
	}

	done := make(chan struct{})
	go func() {
		conn := &nopReadWriteCloser{closed: make(chan struct{})}
		mgr.HandleClientH2(conn, claims)
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mgr.mu.Lock()
		_, ok := mgr.listeners[tl.addr]
		mgr.mu.Unlock()
		if !ok {
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("HandleClientH2 did not return after idle timeout")
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatal("idle reverse listener was not reaped")
}

func TestReverseTunnelManagerDoesNotTimeoutAcquiredConnection(t *testing.T) {
	mgr := NewReverseTunnelManager(0, 50*time.Millisecond)
	t.Cleanup(mgr.Close)
	tl := &tunnelListener{
		addr: "test",
		quit: make(chan struct{}),
	}

	conn := &nopReadWriteCloser{closed: make(chan struct{})}
	wait := &waitingConn{
		h2Conn:   conn,
		acquired: make(chan struct{}),
		done:     make(chan struct{}),
	}

	done := make(chan struct{})
	go func() {
		mgr.waitForUseOrTimeout(tl, wait)
		close(done)
	}()

	wait.markAcquired()

	select {
	case <-done:
		t.Fatal("waitForUseOrTimeout() returned before forwarding completed")
	case <-time.After(2 * mgr.idleTimeout):
	}

	select {
	case <-conn.closed:
		t.Fatal("acquired connection was closed by idle timeout")
	default:
	}

	wait.finish(false)

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("waitForUseOrTimeout() did not return after completion")
	}
}

func TestReverseTunnelManagerPurgesFinishedWaitersBeforeEnqueue(t *testing.T) {
	mgr := NewReverseTunnelManager(0, time.Second)
	t.Cleanup(mgr.Close)
	tl := &tunnelListener{
		addr:    "test",
		waitCap: 1,
		quit:    make(chan struct{}),
	}
	tl.queueCond = sync.NewCond(&tl.queueMu)

	stale := &waitingConn{done: make(chan struct{})}
	stale.finish(false)
	tl.waiting = append(tl.waiting, stale)

	fresh := &waitingConn{done: make(chan struct{})}
	if !mgr.enqueueWaitingConn(tl, fresh) {
		t.Fatal("enqueueWaitingConn() failed to purge stale waiter")
	}

	got, ok := mgr.acquireWaitingConn(tl)
	if !ok || got != fresh {
		t.Fatalf("acquireWaitingConn() got %#v, ok=%v; want fresh waiter", got, ok)
	}
}

func TestReverseTunnelManagerKeepsListenerWhileIncomingConnectionIsPending(t *testing.T) {
	mgr := NewReverseTunnelManager(0, 50*time.Millisecond)
	t.Cleanup(mgr.Close)
	tl := &tunnelListener{
		addr:     "test",
		waitCap:  1,
		quit:     make(chan struct{}),
		lastUsed: time.Now().Add(-time.Second),
	}
	tl.queueCond = sync.NewCond(&tl.queueMu)
	mgr.listeners[tl.addr] = tl

	serverConn, clientConn := net.Pipe()
	blocking := &blockingReadWriteCloser{
		readStarted: make(chan struct{}),
		release:     make(chan struct{}),
		closed:      make(chan struct{}),
	}
	wait := &waitingConn{h2Conn: blocking, done: make(chan struct{})}
	tl.waiting = append(tl.waiting, wait)

	done := make(chan struct{})
	mgr.beginIncoming(tl)
	go func() {
		mgr.handleIncoming(tl, serverConn)
		close(done)
	}()

	select {
	case <-blocking.readStarted:
	case <-time.After(time.Second):
		t.Fatal("forwarding did not start")
	}

	mgr.reapIdleListenersOnce(time.Now())

	mgr.mu.Lock()
	_, ok := mgr.listeners[tl.addr]
	mgr.mu.Unlock()
	if !ok {
		t.Fatal("listener was reaped while handling an incoming connection")
	}

	_ = blocking.Close()
	_ = clientConn.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handleIncoming() did not return")
	}
}

func TestReverseTunnelManagerEnqueueWaitsForSpaceWithoutDeadlock(t *testing.T) {
	mgr := NewReverseTunnelManager(0, time.Second)
	t.Cleanup(mgr.Close)
	tl := &tunnelListener{
		addr:    "test",
		waitCap: 1,
		quit:    make(chan struct{}),
	}
	tl.queueCond = sync.NewCond(&tl.queueMu)

	first := &waitingConn{done: make(chan struct{})}
	second := &waitingConn{done: make(chan struct{})}
	tl.waiting = append(tl.waiting, first)

	enqueueDone := make(chan bool, 1)
	go func() {
		enqueueDone <- mgr.enqueueWaitingConn(tl, second)
	}()

	time.Sleep(20 * time.Millisecond)

	got, ok := mgr.acquireWaitingConn(tl)
	if !ok || got != first {
		t.Fatalf("acquireWaitingConn() got %#v, ok=%v; want first waiter", got, ok)
	}

	select {
	case ok := <-enqueueDone:
		if !ok {
			t.Fatal("enqueueWaitingConn() returned false")
		}
	case <-time.After(time.Second):
		t.Fatal("enqueueWaitingConn() did not complete after space became available")
	}

	got, ok = mgr.acquireWaitingConn(tl)
	if !ok || got != second {
		t.Fatalf("acquireWaitingConn() got %#v, ok=%v; want second waiter", got, ok)
	}
}
