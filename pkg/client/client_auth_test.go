package client

import (
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/kad/wstunnel-go/pkg/protocol"
)

func TestAuthenticateHTTPProxy(t *testing.T) {
	creds := &protocol.Credentials{Username: "admin", Password: "secret"}
	valid := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:secret"))
	invalid := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:wrong"))

	if !authenticateHTTPProxy(valid, creds) {
		t.Fatal("authenticateHTTPProxy() rejected valid credentials")
	}
	if authenticateHTTPProxy(invalid, creds) {
		t.Fatal("authenticateHTTPProxy() accepted invalid credentials")
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
	_, _ = clientConn.Write([]byte{0x05})
	_, _ = clientConn.Write([]byte("wrong"))

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
