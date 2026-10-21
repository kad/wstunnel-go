package server

import (
	"bufio"
	"crypto/hmac"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kad/wstunnel-go/pkg/protocol"
)

// maxProxyRequestHead bounds how much of a visitor's request a reverse HTTP
// proxy listener reads to find the target.
const maxProxyRequestHead = 32 << 10

// dynamicVisitor is a visitor of a reverse listener whose target it named itself
// (SOCKS5 or HTTP proxy), after the front-end protocol was spoken with it.
type dynamicVisitor struct {
	conn net.Conn // carries what the visitor sent after the request, if anything
	host string
	port uint16
	// reply tells the visitor whether the connection was made. A failed one is
	// ended by the caller.
	reply func(ok bool) error
}

// readHTTPProxyRequest reads the request of a visitor of a reverse HTTP proxy
// listener. A CONNECT request is answered once the tunnel is up. Any other
// method must carry an absolute URL, and exactly that one request is sent to the
// target, rewritten for it (see oneRequestConn); so only plain HTTP works that
// way. Rust replays the visitor's bytes as they came instead.
func readHTTPProxyRequest(conn net.Conn, creds *protocol.Credentials) (*dynamicVisitor, error) {
	_ = conn.SetDeadline(time.Now().Add(socks5HandshakeTimeout))
	defer func() { _ = conn.SetDeadline(time.Time{}) }()

	// Only the head is bounded; the limit is lifted once it is parsed, for the
	// body and for what a CONNECT visitor sends after its request.
	lim := &io.LimitedReader{R: conn, N: maxProxyRequestHead}
	br := bufio.NewReaderSize(lim, 4096)
	req, err := http.ReadRequest(br)
	lim.N = math.MaxInt64
	if err != nil {
		_ = writeProxyStatus(conn, http.StatusBadRequest, nil)
		return nil, err
	}

	if !proxyCredentialsMatch(creds, req.Header.Get("Proxy-Authorization")) {
		_ = writeProxyStatus(conn, http.StatusProxyAuthRequired, http.Header{"Proxy-Authenticate": []string{`Basic realm="wstunnel"`}})
		return nil, errors.New("http proxy authentication failed")
	}

	var host string
	var port uint16
	connect := req.Method == http.MethodConnect
	if connect {
		host, port, err = splitProxyTarget(req.Host, 443)
	} else {
		if req.URL == nil || req.URL.Host == "" {
			err = errors.New("the request has no absolute URL")
		} else {
			host, port, err = splitProxyTarget(req.URL.Host, 80)
		}
	}
	if err != nil {
		_ = writeProxyStatus(conn, http.StatusBadRequest, nil)
		return nil, fmt.Errorf("invalid http proxy target: %w", err)
	}

	if !connect {
		return &dynamicVisitor{
			conn: newOneRequestConn(conn, req),
			host: host,
			port: port,
			// The target answers a request that went through. One that could not
			// be handed to a client gets an error response instead of an
			// unexplained close.
			reply: func(ok bool) error {
				if ok {
					return nil
				}
				return writeProxyStatus(conn, http.StatusBadGateway, nil)
			},
		}, nil
	}

	// What the visitor sent after the CONNECT request is already buffered.
	rest, _ := br.Peek(br.Buffered())
	return &dynamicVisitor{
		conn: &prefixConn{Conn: conn, prefix: append([]byte(nil), rest...)},
		host: host,
		port: port,
		reply: func(ok bool) error {
			if !ok {
				return writeProxyStatus(conn, http.StatusBadGateway, nil)
			}
			_, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
			return err
		},
	}, nil
}

// oneRequestConn presents a plain proxy request to the target, and nothing else
// the visitor sends. The request is written again from the parsed form, in the
// absolute form a proxy sends, so the credentials meant for this proxy
// (Proxy-Authorization) and Proxy-Connection are dropped whatever the layout of
// the visitor's headers was, the body keeps its framing, and Connection: close
// makes the target end the exchange. Without that, a later request on the same
// connection would reach the first request's target with its credentials. What
// the visitor sends after the request is read and discarded.
type oneRequestConn struct {
	net.Conn
	src  *io.PipeReader
	sent bool // the request has been read out
}

func newOneRequestConn(conn net.Conn, req *http.Request) *oneRequestConn {
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("Proxy-Connection")
	req.Close = true
	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(req.WriteProxy(pw)) }()
	return &oneRequestConn{Conn: conn, src: pr}
}

func (c *oneRequestConn) Read(p []byte) (int, error) {
	if !c.sent {
		n, err := c.src.Read(p)
		if err != io.EOF {
			return n, err
		}
		c.sent = true
		if n > 0 {
			return n, nil
		}
	}
	// The request is out. Reads go on, because ending them would end the
	// exchange before the answer is back, but they carry nothing further.
	var scratch [512]byte
	for {
		if _, err := c.Conn.Read(scratch[:]); err != nil {
			return 0, err
		}
	}
}

func (c *oneRequestConn) Close() error {
	_ = c.src.Close()
	return c.Conn.Close()
}

// splitProxyTarget splits host and port of a proxy target, with a default port
// when it names none.
func splitProxyTarget(hostport string, defaultPort uint16) (string, uint16, error) {
	host, ps, err := net.SplitHostPort(hostport)
	if err != nil {
		// No port, possibly a bare IPv6 address in brackets.
		host, ps = strings.TrimSuffix(strings.TrimPrefix(hostport, "["), "]"), ""
	}
	port := defaultPort
	if ps != "" {
		n, perr := strconv.ParseUint(ps, 10, 16)
		if perr != nil {
			return "", 0, fmt.Errorf("invalid port %q", ps)
		}
		port = uint16(n)
	}
	if host == "" || port == 0 {
		return "", 0, errors.New("empty host or port 0")
	}
	return host, port, nil
}

// proxyCredentialsMatch checks a Proxy-Authorization header against the
// listener's credentials. Both halves are compared as digests, and whatever the
// first gives.
func proxyCredentialsMatch(creds *protocol.Credentials, header string) bool {
	if creds == nil {
		return true
	}
	scheme, token, _ := strings.Cut(strings.TrimSpace(header), " ")
	if !strings.EqualFold(scheme, "Basic") {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(token))
	if err != nil {
		return false
	}
	user, pass, _ := strings.Cut(string(decoded), ":")
	okUser := hmac.Equal(digest([]byte(user)), digest([]byte(creds.Username)))
	okPass := hmac.Equal(digest([]byte(pass)), digest([]byte(creds.Password)))
	return okUser && okPass
}

func writeProxyStatus(w io.Writer, code int, extra http.Header) error {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n", code, http.StatusText(code))
	for k, vs := range extra {
		for _, v := range vs {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	b.WriteString("\r\n")
	_, err := io.WriteString(w, b.String())
	return err
}

// prefixConn is a connection whose reads start with bytes that were already
// taken from it.
type prefixConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}
