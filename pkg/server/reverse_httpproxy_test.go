package server

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/kad/wstunnel-go/pkg/protocol"
)

// runProxyRequest sends request to readHTTPProxyRequest through a pipe and
// returns what it made of it, and what it wrote back to the visitor.
func runProxyRequest(t *testing.T, creds *protocol.Credentials, request string) (v *dynamicVisitor, written string, err error) {
	t.Helper()
	server, client := net.Pipe()
	defer func() { _ = client.Close() }()
	got := make(chan string, 1)
	go func() {
		_, _ = io.WriteString(client, request)
		_ = client.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		b, _ := io.ReadAll(client)
		got <- string(b)
	}()
	type result struct {
		v   *dynamicVisitor
		err error
	}
	res := make(chan result, 1)
	go func() {
		v, err := readHTTPProxyRequest(server, creds)
		res <- result{v, err}
	}()
	select {
	case r := <-res:
		if r.err != nil {
			_ = server.Close() // lets the writer's read end
		}
		select {
		case written = <-got:
		case <-time.After(3 * time.Second):
		}
		return r.v, written, r.err
	case <-time.After(3 * time.Second):
		t.Fatal("readHTTPProxyRequest did not return")
		return nil, "", nil
	}
}

func TestReadHTTPProxyRequestConnect(t *testing.T) {
	cases := []struct {
		name     string
		request  string
		wantHost string
		wantPort uint16
	}{
		{"port", "CONNECT example.org:8443 HTTP/1.1\r\nHost: example.org:8443\r\n\r\n", "example.org", 8443},
		{"default port", "CONNECT example.org HTTP/1.1\r\nHost: example.org\r\n\r\n", "example.org", 443},
		{"ipv6", "CONNECT [2001:db8::1]:80 HTTP/1.1\r\nHost: [2001:db8::1]:80\r\n\r\n", "2001:db8::1", 80},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, _, err := runProxyRequest(t, nil, tc.request)
			if err != nil || v.host != tc.wantHost || v.port != tc.wantPort {
				t.Fatalf("got %+v err=%v, want %s:%d", v, err, tc.wantHost, tc.wantPort)
			}
		})
	}
}

// Bytes the visitor sent right after a CONNECT request are not lost.
func TestReadHTTPProxyRequestKeepsEarlyTunnelBytes(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = server.Close(); _ = client.Close() }()
	go func() {
		_, _ = io.WriteString(client, "CONNECT a.example:80 HTTP/1.1\r\nHost: a.example:80\r\n\r\nearly bytes")
	}()
	v, err := readHTTPProxyRequest(server, nil)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("early bytes"))
	if _, err := io.ReadFull(v.conn, buf); err != nil || string(buf) != "early bytes" {
		t.Fatalf("read %q, %v; want the early bytes", buf, err)
	}
}

func TestReadHTTPProxyRequestRejects(t *testing.T) {
	creds := &protocol.Credentials{Username: "admin", Password: "secret"}
	cases := []struct {
		name    string
		creds   *protocol.Credentials
		request string
		want    string // status line prefix written back
	}{
		{"no host in a plain request", nil, "GET / HTTP/1.1\r\nHost: example.org\r\n\r\n", "HTTP/1.1 400"},
		{"port 0", nil, "CONNECT example.org:0 HTTP/1.1\r\nHost: example.org:0\r\n\r\n", "HTTP/1.1 400"},
		{"garbage", nil, "\x00\x01\x02 nonsense\r\n\r\n", "HTTP/1.1 400"},
		{"credentials missing", creds, "CONNECT example.org:80 HTTP/1.1\r\nHost: example.org:80\r\n\r\n", "HTTP/1.1 407"},
		{"wrong password", creds, "CONNECT example.org:80 HTTP/1.1\r\nHost: example.org:80\r\nProxy-Authorization: Basic YWRtaW46d3Jvbmc=\r\n\r\n", "HTTP/1.1 407"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, written, err := runProxyRequest(t, tc.creds, tc.request)
			if err == nil || v != nil {
				t.Fatalf("the request was accepted: %+v", v)
			}
			if !strings.HasPrefix(written, tc.want) {
				t.Fatalf("visitor was told %q, want %q", written, tc.want)
			}
			if tc.want == "HTTP/1.1 407" && !strings.Contains(written, `Proxy-Authenticate: Basic realm="wstunnel"`) {
				t.Errorf("no challenge in %q", written)
			}
		})
	}
}

func TestReadHTTPProxyRequestAcceptsRightCredentials(t *testing.T) {
	creds := &protocol.Credentials{Username: "admin", Password: "secret"}
	v, _, err := runProxyRequest(t, creds, "CONNECT example.org:80 HTTP/1.1\r\nHost: example.org:80\r\nProxy-Authorization: Basic YWRtaW46c2VjcmV0\r\n\r\n")
	if err != nil || v.host != "example.org" {
		t.Fatalf("got %+v, %v", v, err)
	}
}

// readUntilQuiet reads what the target would receive until nothing more comes.
func readUntilQuiet(t *testing.T, c net.Conn) string {
	t.Helper()
	var out []byte
	buf := make([]byte, 4096)
	for {
		_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n, err := c.Read(buf)
		out = append(out, buf[:n]...)
		if err != nil {
			return string(out)
		}
	}
}

// A plain request reaches the target in the form a proxy sends it, with the
// credentials meant for the proxy gone whatever the layout of the headers (case,
// repeated, folded, LF-only), and the rest of the request and its body kept.
func TestReadHTTPProxyRequestRewritesPlainRequest(t *testing.T) {
	creds := &protocol.Credentials{Username: "admin", Password: "secret"}
	inputs := map[string]string{
		"crlf": "POST http://example.org:8080/submit?q=1 HTTP/1.1\r\n" +
			"Host: example.org:8080\r\n" +
			"proxy-authorization: Basic YWRtaW46c2VjcmV0\r\n" +
			"Accept: */*\r\n" +
			"PROXY-AUTHORIZATION: Basic YWRtaW46c2VjcmV0\r\n" +
			" folded-continuation\r\n" +
			"Proxy-Connection: keep-alive\r\n" +
			"Authorization: Bearer for-the-origin\r\n" +
			"Content-Length: 5\r\n\r\nhello",
		"lf only": "POST http://example.org:8080/submit?q=1 HTTP/1.1\n" +
			"Host: example.org:8080\n" +
			"Proxy-Authorization: Basic YWRtaW46c2VjcmV0\n" +
			"Accept: */*\n" +
			"Authorization: Bearer for-the-origin\n" +
			"Content-Length: 5\n\nhello",
	}
	for name, in := range inputs {
		t.Run(name, func(t *testing.T) {
			server, client := net.Pipe()
			defer func() { _ = server.Close(); _ = client.Close() }()
			go func() { _, _ = io.WriteString(client, in) }()
			v, err := readHTTPProxyRequest(server, creds)
			if err != nil {
				t.Fatal(err)
			}
			got := readUntilQuiet(t, v.conn)
			if strings.Contains(strings.ToLower(got), "proxy-") || strings.Contains(got, "YWRtaW46") || strings.Contains(got, "folded-continuation") {
				t.Fatalf("proxy credentials or proxy headers reached the target:\n%s", got)
			}
			req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(got)))
			if err != nil {
				t.Fatalf("the target got an unparsable request: %v\n%s", err, got)
			}
			body, _ := io.ReadAll(req.Body)
			if req.Method != "POST" || req.Host != "example.org:8080" || req.URL.RequestURI() != "/submit?q=1" ||
				req.Header.Get("Accept") != "*/*" || req.Header.Get("Authorization") != "Bearer for-the-origin" ||
				string(body) != "hello" || !req.Close {
				t.Fatalf("request not kept: %+v body %q", req, body)
			}
		})
	}
}

// Only the one request goes to the first request's target: a second one on the
// same connection, for another origin or with its own credentials, is not
// forwarded.
func TestReadHTTPProxyRequestForwardsOnlyOneRequest(t *testing.T) {
	first := "GET http://first.example/a HTTP/1.1\r\nHost: first.example\r\n\r\n"
	second := "GET http://second.example/b HTTP/1.1\r\nHost: second.example\r\nProxy-Authorization: Basic c2VjcmV0\r\n\r\n"
	server, client := net.Pipe()
	defer func() { _ = server.Close(); _ = client.Close() }()
	go func() {
		_, _ = io.WriteString(client, first+second)
		_, _ = io.Copy(io.Discard, client)
	}()
	v, err := readHTTPProxyRequest(server, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := readUntilQuiet(t, v.conn)
	if !strings.Contains(got, "GET http://first.example/a") {
		t.Fatalf("the first request did not arrive: %q", got)
	}
	if strings.Contains(got, "second.example") || strings.Contains(got, "c2VjcmV0") {
		t.Fatalf("a second request was forwarded: %q", got)
	}
}

// A plain request that could not be handed to a client is answered with a 502,
// not left to end in an unexplained close.
func TestPlainProxyRequestGets502WhenNoClientTakesIt(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = server.Close(); _ = client.Close() }()
	go func() { _, _ = io.WriteString(client, "GET http://example.org/ HTTP/1.1\r\nHost: example.org\r\n\r\n") }()
	v, err := readHTTPProxyRequest(server, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.reply(true); err != nil {
		t.Fatalf("success must write nothing: %v", err)
	}
	got := make(chan string, 1)
	go func() {
		_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
		b := make([]byte, 512)
		n, _ := client.Read(b)
		got <- string(b[:n])
	}()
	if err := v.reply(false); err != nil {
		t.Fatal(err)
	}
	if line := <-got; !strings.HasPrefix(line, "HTTP/1.1 502") {
		t.Fatalf("visitor got %q, want a 502", line)
	}
}
