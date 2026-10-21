package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"github.com/kad/wstunnel-go/pkg/protocol"
	"github.com/kad/wstunnel-go/pkg/wst"
)

// A reverse SOCKS5 listener runs the SOCKS5 server on the tunnel server. What a
// visitor asks to reach is only known once it has sent its request, and the far
// client must connect to that target. So the client's HTTP request is held
// without a reply while it waits in the pool; when a visitor has completed the
// SOCKS5 handshake the request is answered, and the target travels to the client
// in a Cookie response header carrying a JWT, as Rust does.

// lazyUpgrade completes a held WebSocket upgrade with the given extra headers.
// Exactly one is set, for the transport the client used.
type lazyUpgrade struct {
	wst     func(extra http.Header) (*wst.Conn, error)
	gorilla func(extra http.Header) (*websocket.Conn, error)
	// stream answers an HTTP/2 request or a WebTransport stream. The extra
	// headers go in the response headers, or in the stream's JWT preamble.
	stream func(extra http.Header) (io.ReadWriteCloser, error)
}

// HandleDynamicClient parks a reverse request whose reply is held back. It
// returns when the request ends: the client went away (gone), the connection
// was used and has finished, or the pool gave up on it. gone is the request's
// context, which the HTTP server cancels when the client disconnects.
//
// It returns an error, with nothing answered yet, when the request cannot be
// held at all: the listener cannot be set up or is going away. The caller turns
// that into an HTTP error, so the client sees a failure and backs off instead of
// retrying an empty reply at once.
func (m *ReverseTunnelManager) HandleDynamicClient(claims *protocol.JwtTunnelConfig, up lazyUpgrade, gone <-chan struct{}) error {
	tl, bindAddr, err := m.getOrCreateListener(claims)
	if err != nil {
		slog.Error("Reverse tunnel: failed to listen", "addr", bindAddr, "err", err)
		return err
	}

	wait := &waitingConn{
		acquired: make(chan struct{}),
		done:     make(chan struct{}),
		gone:     gone,
	}
	// lazy runs under wait.connMu (see completeUpgrade), so it sets the
	// connection fields directly.
	wait.lazy = func(extra http.Header) error {
		switch {
		case up.wst != nil:
			c, err := up.wst(extra)
			if err != nil {
				return err
			}
			wait.wsConn = c
		case up.gorilla != nil:
			c, err := up.gorilla(extra)
			if err != nil {
				return err
			}
			wait.gorillaConn = c
		case up.stream != nil:
			c, err := up.stream(extra)
			if err != nil {
				return err
			}
			wait.h2Conn = c
		default:
			return errors.New("no upgrade for this transport")
		}
		return nil
	}

	// A held request can wait for a place in a full pool, and its client can go
	// away meanwhile. Watch for that from the start, and wake the queue so the
	// blocked admission notices.
	if gone != nil {
		stopWatching := make(chan struct{})
		defer close(stopWatching)
		go func() {
			select {
			case <-gone:
				wait.abort()
				tl.queueMu.Lock()
				if tl.queueCond != nil {
					tl.queueCond.Broadcast()
				}
				tl.queueMu.Unlock()
			case <-wait.done:
			case <-stopWatching:
			}
		}()
	}

	if m.enqueueWaitingConn(tl, wait) {
		m.touchListener(tl)
		slog.Info("Reverse tunnel: client request held in pool", "tunnel_id", claims.ID, "addr", bindAddr, "proto", getProtoName(claims.Protocol))
		m.waitForUseOrTimeout(tl, wait)
		return nil
	}
	wait.finish(true)
	return fmt.Errorf("the reverse listener on %s is closing", bindAddr)
}

var errRequestEnded = errors.New("the held request already ended")

// completeUpgrade runs the held upgrade, unless the request ended first. It
// holds connMu, which finish also takes, so the two never overlap.
func (w *waitingConn) completeUpgrade(extra http.Header) error {
	w.connMu.Lock()
	defer w.connMu.Unlock()
	select {
	case <-w.done:
		return errRequestEnded
	default:
	}
	return w.lazy(extra)
}

// answerHeldRequest completes the held upgrade of a waiting request, with the
// visitor's target in the Cookie header.
func (m *ReverseTunnelManager) answerHeldRequest(wait *waitingConn, host string, port uint16, udp bool) error {
	if wait.lazy == nil {
		return errors.New("the client connection was already upgraded and cannot carry a target")
	}
	cookie, err := m.targetCookie(host, port, udp)
	if err != nil {
		return err
	}
	return wait.completeUpgrade(http.Header{"Cookie": []string{cookie}})
}

// socks5Reply sends a SOCKS5 reply with the given code and a zero bind address.
func socks5Reply(conn net.Conn, code byte) error {
	_, err := conn.Write([]byte{0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}

const (
	socks5Succeeded           = 0x00
	socks5GeneralFailure      = 0x01
	socks5CommandNotSupported = 0x07
	socks5AddrNotSupported    = 0x08
)

// readSocks5Request performs the SOCKS5 greeting (with username and password
// when the tunnel was set up with credentials) and reads the visitor's CONNECT
// request. It sends no reply to the request: that waits until a client has
// taken the connection.
func readSocks5Request(conn net.Conn, creds *protocol.Credentials) (host string, port uint16, err error) {
	cmd, host, port, err := readSocks5Command(conn, creds)
	if err != nil {
		return "", 0, err
	}
	if cmd != socks5CmdConnect {
		_ = socks5Reply(conn, socks5CommandNotSupported)
		return "", 0, fmt.Errorf("unsupported socks command: %d", cmd)
	}
	return host, port, nil
}

const (
	socks5CmdConnect      = 0x01
	socks5CmdUDPAssociate = 0x03
)

// readSocks5Command performs the SOCKS5 greeting (with username and password
// when the tunnel was set up with credentials) and reads the visitor's command.
// It sends no reply to a CONNECT: that waits until a client has taken the
// connection. A command that is neither CONNECT nor UDP ASSOCIATE is returned
// as read, for the caller to refuse.
func readSocks5Command(conn net.Conn, creds *protocol.Credentials) (cmd byte, host string, port uint16, err error) {
	_ = conn.SetDeadline(time.Now().Add(socks5HandshakeTimeout))
	defer func() { _ = conn.SetDeadline(time.Time{}) }()
	buf := make([]byte, 256)

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return 0, "", 0, err
	}
	if buf[0] != 0x05 {
		return 0, "", 0, fmt.Errorf("invalid socks version: %d", buf[0])
	}
	nmethods := int(buf[1])
	if _, err := io.ReadFull(conn, buf[:nmethods]); err != nil {
		return 0, "", 0, err
	}
	offers := func(method byte) bool {
		for _, m := range buf[:nmethods] {
			if m == method {
				return true
			}
		}
		return false
	}

	if creds != nil {
		if !offers(0x02) {
			_, _ = conn.Write([]byte{0x05, 0xFF})
			return 0, "", 0, errors.New("socks5 client offered no username and password method")
		}
		if _, err := conn.Write([]byte{0x05, 0x02}); err != nil {
			return 0, "", 0, err
		}
		if err := readSocks5Credentials(conn, creds); err != nil {
			return 0, "", 0, err
		}
	} else {
		if !offers(0x00) {
			_, _ = conn.Write([]byte{0x05, 0xFF})
			return 0, "", 0, errors.New("socks5 client offered no unauthenticated method")
		}
		if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
			return 0, "", 0, err
		}
	}

	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return 0, "", 0, err
	}
	if buf[0] != 0x05 {
		return 0, "", 0, fmt.Errorf("invalid socks version: %d", buf[0])
	}
	cmd = buf[1]
	if cmd != socks5CmdConnect && cmd != socks5CmdUDPAssociate {
		_ = socks5Reply(conn, socks5CommandNotSupported)
		return 0, "", 0, fmt.Errorf("unsupported socks command: %d", cmd)
	}
	switch buf[3] {
	case 0x01:
		if _, err := io.ReadFull(conn, buf[:4]); err != nil {
			return 0, "", 0, err
		}
		host = net.IP(buf[:4]).String()
	case 0x03:
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return 0, "", 0, err
		}
		sz := int(buf[0])
		if _, err := io.ReadFull(conn, buf[:sz]); err != nil {
			return 0, "", 0, err
		}
		host = string(buf[:sz])
	case 0x04:
		if _, err := io.ReadFull(conn, buf[:16]); err != nil {
			return 0, "", 0, err
		}
		host = net.IP(buf[:16]).String()
	default:
		_ = socks5Reply(conn, socks5AddrNotSupported)
		return 0, "", 0, fmt.Errorf("unsupported address type: %d", buf[3])
	}
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return 0, "", 0, err
	}
	port = binary.BigEndian.Uint16(buf[:2])
	// A CONNECT target the client could not dial would make it back off from the
	// server. Refuse it here, where only this visitor is affected. (UDP ASSOCIATE
	// names the address the visitor sends from, usually 0.0.0.0:0.)
	if cmd == socks5CmdConnect && (host == "" || port == 0) {
		_ = socks5Reply(conn, socks5GeneralFailure)
		return 0, "", 0, fmt.Errorf("invalid socks target %q port %d", host, port)
	}
	return cmd, host, port, nil
}

func digest(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// readSocks5Credentials reads the RFC 1929 username and password and checks them.
func readSocks5Credentials(conn net.Conn, creds *protocol.Credentials) error {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return err
	}
	if hdr[0] != 0x01 {
		return fmt.Errorf("invalid auth version: %d", hdr[0])
	}
	user := make([]byte, hdr[1])
	if _, err := io.ReadFull(conn, user); err != nil {
		return err
	}
	plen := make([]byte, 1)
	if _, err := io.ReadFull(conn, plen); err != nil {
		return err
	}
	pass := make([]byte, plen[0])
	if _, err := io.ReadFull(conn, pass); err != nil {
		return err
	}
	// Both are compared, whatever the first gives, and as fixed-size digests.
	okUser := hmac.Equal(digest(user), digest([]byte(creds.Username)))
	okPass := hmac.Equal(digest(pass), digest([]byte(creds.Password)))
	if !okUser || !okPass {
		_, _ = conn.Write([]byte{0x01, 0x01})
		return errors.New("socks5 authentication failed")
	}
	_, err := conn.Write([]byte{0x01, 0x00})
	return err
}

// targetCookie builds the Cookie header value that tells the client what the
// visitor asked for: a JWT whose claims are the target, as Rust's
// tunnel_to_jwt_token produces. Every client reads it without checking the
// signature. An IPv6 address is bracketed because Rust parses the host as a URL
// host.
func (m *ReverseTunnelManager) targetCookie(host string, port uint16, udp bool) (string, error) {
	if m.signCookie == nil {
		return "", errors.New("no signer for the target cookie")
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	proto := protocol.LocalProtocol{Tcp: &protocol.TcpProtocol{ProxyProtocol: false}}
	if udp {
		proto = protocol.LocalProtocol{Udp: &protocol.UdpProtocol{}}
	}
	claims := protocol.JwtTunnelConfig{
		ID:       "00000000-0000-0000-0000-000000000000",
		Protocol: proto,
		Remote:   host,
		Port:     port,
	}
	return m.signCookie(claims)
}

// withCookieSigner sets how the target cookie is signed.
func (m *ReverseTunnelManager) withCookieSigner(sign func(protocol.JwtTunnelConfig) (string, error)) *ReverseTunnelManager {
	m.signCookie = sign
	return m
}

// cookieSigner returns a signer for the target cookie. It signs with a key
// derived from the server's JWT secret (or the legacy one when none is set), not
// with the secret itself. The cookie has the shape of a tunnel request, and
// clients read it without checking the signature, so a cookie signed with the
// request key could be replayed as a signed forward tunnel request by a client
// that never held the secret. Signed with its own key it fails that check.
func cookieSigner(secret string) func(protocol.JwtTunnelConfig) (string, error) {
	if secret == "" {
		secret = "champignonfrais"
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("wstunnel-go reverse target cookie"))
	key := mac.Sum(nil)
	return func(c protocol.JwtTunnelConfig) (string, error) {
		return jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString(key)
	}
}
