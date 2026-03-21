package client

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/kad/wstunnel-go/pkg/protocol"
)

func TestAuthenticateHTTPProxy(t *testing.T) {
	creds := &protocol.Credentials{Username: "admin", Password: "secret"}
	valid := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:secret"))
	validLower := "basic " + base64.StdEncoding.EncodeToString([]byte("admin:secret"))
	invalid := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:wrong"))
	sameLengthInvalid := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:secrex"))

	if !authenticateHTTPProxy(valid, creds) {
		t.Fatal("authenticateHTTPProxy() rejected valid credentials")
	}
	if !authenticateHTTPProxy(validLower, creds) {
		t.Fatal("authenticateHTTPProxy() rejected valid lowercase basic scheme")
	}
	if authenticateHTTPProxy(invalid, creds) {
		t.Fatal("authenticateHTTPProxy() accepted invalid credentials")
	}
	if authenticateHTTPProxy(sameLengthInvalid, creds) {
		t.Fatal("authenticateHTTPProxy() accepted same-length invalid credentials")
	}
	if authenticateHTTPProxy("Bearer token", creds) {
		t.Fatal("authenticateHTTPProxy() accepted non-basic credentials")
	}
	if authenticateHTTPProxy("", creds) {
		t.Fatal("authenticateHTTPProxy() accepted missing credentials")
	}
	if !authenticateHTTPProxy("", nil) {
		t.Fatal("authenticateHTTPProxy() rejected unauthenticated proxy")
	}
}

func TestHandleSocks5RejectsInvalidCredentials(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	c := &Client{}
	errCh := make(chan error, 1)
	go func() {
		_, _, err := c.handleSocks5(serverConn, &protocol.Credentials{Username: "admin", Password: "secret"})
		errCh <- err
	}()

	_, _ = clientConn.Write([]byte{0x05, 0x01, 0x02})
	reply := make([]byte, 2)
	if _, err := io.ReadFull(clientConn, reply); err != nil {
		t.Fatalf("io.ReadFull() error = %v", err)
	}
	if reply[0] != 0x05 || reply[1] != 0x02 {
		t.Fatalf("method selection = %v, want [5 2]", reply)
	}

	_, _ = clientConn.Write([]byte{0x01, 0x05})
	_, _ = clientConn.Write([]byte("admin"))
	_, _ = clientConn.Write([]byte{0x06})
	_, _ = clientConn.Write([]byte("secrex"))

	authReply := make([]byte, 2)
	if _, err := io.ReadFull(clientConn, authReply); err != nil {
		t.Fatalf("io.ReadFull() error = %v", err)
	}
	if authReply[0] != 0x01 || authReply[1] != 0x01 {
		t.Fatalf("auth status = %v, want [1 1]", authReply)
	}

	if err := <-errCh; err == nil {
		t.Fatal("handleSocks5() unexpectedly accepted invalid credentials")
	}
}

func TestHandleSocks5AcceptsValidCredentials(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	c := &Client{}
	type result struct {
		host string
		port uint16
		err  error
	}
	resultCh := make(chan result, 1)
	go func() {
		host, port, err := c.handleSocks5(serverConn, &protocol.Credentials{Username: "admin", Password: "secret"})
		resultCh <- result{host: host, port: port, err: err}
	}()

	_, _ = clientConn.Write([]byte{0x05, 0x01, 0x02})
	reply := make([]byte, 2)
	if _, err := io.ReadFull(clientConn, reply); err != nil {
		t.Fatalf("io.ReadFull() error = %v", err)
	}
	if reply[1] != 0x02 {
		t.Fatalf("method selection = %v, want auth method", reply)
	}

	_, _ = clientConn.Write([]byte{0x01, 0x05})
	_, _ = clientConn.Write([]byte("admin"))
	_, _ = clientConn.Write([]byte{0x06})
	_, _ = clientConn.Write([]byte("secret"))

	authReply := make([]byte, 2)
	if _, err := io.ReadFull(clientConn, authReply); err != nil {
		t.Fatalf("io.ReadFull() error = %v", err)
	}
	if authReply[0] != 0x01 || authReply[1] != 0x00 {
		t.Fatalf("auth status = %v, want [1 0]", authReply)
	}

	_, _ = clientConn.Write([]byte{0x05, 0x01, 0x00, 0x03, 0x0b})
	_, _ = clientConn.Write([]byte("example.com"))
	_, _ = clientConn.Write([]byte{0x01, 0xbb})

	resp := make([]byte, 10)
	if _, err := io.ReadFull(clientConn, resp); err != nil {
		t.Fatalf("io.ReadFull() error = %v", err)
	}
	if resp[1] != 0x00 {
		t.Fatalf("socks reply = %v, want success", resp)
	}

	got := <-resultCh
	if got.err != nil {
		t.Fatalf("handleSocks5() error = %v", got.err)
	}
	if got.host != "example.com" || got.port != 443 {
		t.Fatalf("handleSocks5() got %s:%d, want example.com:443", got.host, got.port)
	}
}

func TestConnectToGorillaOverWSS(t *testing.T) {
	upgrader := websocket.Upgrader{
		CheckOrigin:  func(r *http.Request) bool { return true },
		Subprotocols: []string{"v1"},
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/events" {
			t.Fatalf("request path = %s, want /v1/events", r.URL.Path)
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatalf("Upgrade() error = %v", err)
		}
		_ = conn.Close()
	}))
	defer server.Close()

	c := NewClient(Config{
		ServerURL:         server.URL,
		PathPrefix:        "v1",
		TlsVerifyCert:     false,
		WebsocketProtocol: "ws",
	})

	conn, resp, err := c.connectToGorilla(protocol.LocalProtocol{Tcp: &protocol.TcpProtocol{}}, "example.com", 443)
	if err != nil {
		t.Fatalf("connectToGorilla() error = %v", err)
	}
	if resp == nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("response = %#v, want status 101", resp)
	}
	_ = conn.Close()
}

func TestConnectToGorillaOverWSSIgnoresClosedPool(t *testing.T) {
	upgrader := websocket.Upgrader{
		CheckOrigin:  func(r *http.Request) bool { return true },
		Subprotocols: []string{"v1"},
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatalf("Upgrade() error = %v", err)
		}
		_ = conn.Close()
	}))
	defer server.Close()

	c := NewClient(Config{
		ServerURL:         server.URL,
		PathPrefix:        "v1",
		TlsVerifyCert:     false,
		WebsocketProtocol: "ws",
	})
	c.pool = &ConnectionPool{}
	c.pool.closed.Store(true)

	conn, resp, err := c.connectToGorilla(protocol.LocalProtocol{Tcp: &protocol.TcpProtocol{}}, "example.com", 443)
	if err != nil {
		t.Fatalf("connectToGorilla() error = %v", err)
	}
	if resp == nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("response = %#v, want status 101", resp)
	}
	_ = conn.Close()
}

func TestConnectToGorillaOverWSSWithClientCertificate(t *testing.T) {
	caCertPEM, _, caCert, caKey := generateCertificateAuthority(t)
	serverCert := generateSignedCertificate(t, caCert, caKey, true, "127.0.0.1")
	clientCert := generateSignedCertificate(t, caCert, caKey, false, "client")

	serverTLSCert, err := tls.X509KeyPair(serverCert.certPEM, serverCert.keyPEM)
	if err != nil {
		t.Fatalf("tls.X509KeyPair() error = %v", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCertPEM) {
		t.Fatal("AppendCertsFromPEM() failed")
	}

	upgrader := websocket.Upgrader{
		CheckOrigin:  func(r *http.Request) bool { return true },
		Subprotocols: []string{"v1"},
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) == 0 {
			t.Fatal("expected client certificate")
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatalf("Upgrade() error = %v", err)
		}
		_ = conn.Close()
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverTLSCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
	}
	server.StartTLS()
	defer server.Close()

	certFile := writeTempFile(t, "client-cert-*.pem", clientCert.certPEM)
	keyFile := writeTempFile(t, "client-key-*.pem", clientCert.keyPEM)

	c := NewClient(Config{
		ServerURL:         server.URL,
		PathPrefix:        "v1",
		TlsVerifyCert:     false,
		TlsClientCert:     certFile,
		TlsClientKey:      keyFile,
		WebsocketProtocol: "ws",
	})

	conn, resp, err := c.connectToGorilla(protocol.LocalProtocol{Tcp: &protocol.TcpProtocol{}}, "example.com", 443)
	if err != nil {
		t.Fatalf("connectToGorilla() error = %v", err)
	}
	if resp == nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("response = %#v, want status 101", resp)
	}
	_ = conn.Close()
}

type certMaterial struct {
	certPEM []byte
	keyPEM  []byte
}

func generateCertificateAuthority(t *testing.T) ([]byte, []byte, *x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
		cert, key
}

func generateSignedCertificate(t *testing.T, caCert *x509.Certificate, caKey *rsa.PrivateKey, server bool, name string) certMaterial {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	if server {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.DNSNames = []string{name, "localhost"}
		tmpl.IPAddresses = []net.IP{net.ParseIP(name)}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}

	return certMaterial{
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
	}
}

func writeTempFile(t *testing.T, pattern string, contents []byte) string {
	t.Helper()

	f, err := os.CreateTemp(t.TempDir(), pattern)
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	if _, err := f.Write(contents); err != nil {
		_ = f.Close()
		t.Fatalf("Write() error = %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	return f.Name()
}
