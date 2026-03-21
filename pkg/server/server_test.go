package server

import (
	"io"
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

func TestConfigYAMLUsesHTTPUpgradePathPrefix(t *testing.T) {
	var cfg Config
	if err := yaml.Unmarshal([]byte("http_upgrade_path_prefix: api\n"), &cfg); err != nil {
		t.Fatalf("yaml.Unmarshal() error = %v", err)
	}

	if cfg.PathPrefix != "api" {
		t.Fatalf("PathPrefix = %q, want %q", cfg.PathPrefix, "api")
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

func TestParseJWTClaimsCompatibilityModeAcceptsUnsignedToken(t *testing.T) {
	srv := NewServer(Config{
		WebsocketProtocol:       "ws",
		InsecureNoJWTValidation: true,
	})

	claims, err := srv.parseJWTClaims(unsignedToken(t))
	if err != nil {
		t.Fatalf("parseJWTClaims() error = %v", err)
	}
	if claims.Remote != "example.com" || claims.Port != 443 {
		t.Fatalf("parseJWTClaims() got %+v", claims)
	}
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

func TestReverseTunnelManagerReapsIdleListener(t *testing.T) {
	mgr := NewReverseTunnelManager(0, 50*time.Millisecond)
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
