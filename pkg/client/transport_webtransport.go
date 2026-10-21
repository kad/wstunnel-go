package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/kad/wstunnel-go/pkg/protocol"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/webtransport-go"
)

type WebTransportClient struct {
	client *Client
	mu     sync.Mutex
	sess   *webtransport.Session
	// sessPinKey records the pinned server addresses sess was dialed for.
	sessPinKey string
}

func NewWebTransportClient(client *Client) *WebTransportClient {
	return &WebTransportClient{client: client}
}

func (w *WebTransportClient) Connect(p protocol.LocalProtocol, remoteHost string, remotePort uint16) (io.ReadWriteCloser, *http.Response, error) {
	requestID := uuid.New().String()
	token, err := w.client.generateJWT(requestID, p, remoteHost, remotePort)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate JWT: %w", err)
	}

	u, err := url.Parse(w.client.Config.ServerURL)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid server url: %w", err)
	}

	isTLS := u.Scheme == "wts" || u.Scheme == "https" || u.Scheme == "wss"
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if isTLS {
			port = "443"
		} else {
			port = "80"
		}
	}

	u.Host = net.JoinHostPort(host, port)
	u.Scheme = "https"
	u.Path = fmt.Sprintf("/%s/events", w.client.Config.PathPrefix)

	ctx := context.Background()

	w.mu.Lock()
	sess := w.sess
	pinKey := strings.Join(w.client.pinnedTargets(u.Host), ",")
	if sess != nil && !sessionReusable(sess, w.sessPinKey, pinKey) {
		// A session whose QUIC connection is gone would fail the first stream
		// open; one dialed for server addresses that are no longer pinned still
		// talks to an address whose packets now follow the tunnel's own routes.
		// Dial a fresh one.
		if !sessionDead(sess) {
			_ = sess.CloseWithError(0, "server addresses changed")
		}
		w.sess = nil
		sess = nil
	}
	if sess == nil {
		var tlsConfig *tls.Config
		if isTLS {
			var err error
			tlsConfig, err = w.client.tlsClientConfig(host)
			if err != nil {
				w.mu.Unlock()
				return nil, nil, err
			}
		} else {
			tlsConfig = &tls.Config{InsecureSkipVerify: true}
		}
		if tlsConfig.NextProtos == nil {
			tlsConfig.NextProtos = []string{"h3"}
		}

		tr := &webtransport.Transport{
			TLSClientConfig: tlsConfig,
			QUICConfig:      newWebTransportQUICConfig(),
		}
		if w.client.socketMark() != 0 || w.client.pinnedTargets(u.Host) != nil {
			// Own dial: marks the socket and/or dials the cached server addresses.
			tr.DialAddr = w.dialMarkedAddr
		}

		headers := http.Header{}
		for k, v := range w.client.Config.Headers {
			headers.Set(k, v)
		}
		for k, v := range w.client.loadHttpHeaders() {
			headers.Set(k, v)
		}
		if w.client.Config.HttpUpgradeCredentials != "" {
			headers.Set("Authorization", w.client.Config.HttpUpgradeCredentials)
		}

		var resp *http.Response
		resp, sess, err = tr.Dial(ctx, u.String(), headers)
		if err != nil {
			w.mu.Unlock()
			return nil, resp, fmt.Errorf("failed to dial WebTransport session: %w", err)
		}
		w.sess = sess
		w.sessPinKey = pinKey
	}
	w.mu.Unlock()

	stream, err := sess.OpenStreamSync(ctx)
	if err != nil {
		w.mu.Lock()
		w.sess = nil
		w.mu.Unlock()
		return nil, nil, fmt.Errorf("failed to open WebTransport stream: %w", err)
	}

	if err := protocol.WriteJWTStreamPreamble(stream, token); err != nil {
		_ = stream.Close()
		return nil, nil, fmt.Errorf("failed to write JWT preamble: %w", err)
	}

	var rwc io.ReadWriteCloser = stream
	if p.Udp != nil || p.ReverseUdp != nil {
		rwc = protocol.NewFramedUDPReadWriteCloser(stream)
	}

	var resp *http.Response
	if p.ReverseSocks5 != nil {
		rwc = reverseStream{stream}
		// The server answers once a visitor has asked for a target, and says
		// which in a JWT preamble on the stream. Surface it as the Cookie header
		// the other transports use, so the reverse loop reads it the same way.
		_ = stream.SetReadDeadline(time.Now().Add(reverseReplyTimeout))
		jwtStr, err := protocol.ReadJWTStreamPreamble(stream)
		_ = stream.SetReadDeadline(time.Time{})
		if err != nil {
			// Abort the stream, both directions: closing only the send side would
			// leave the server holding a request nobody is waiting for.
			stream.CancelRead(0)
			stream.CancelWrite(0)
			// The stream is open, so a timeout here is the server waiting for a
			// visitor.
			return nil, nil, fmt.Errorf("failed to read the target from the server: %w", markReplyTimeout(err, true))
		}
		resp = &http.Response{Header: http.Header{"Cookie": []string{jwtStr}}}
	}

	return rwc, resp, nil
}

// reverseStream is a reverse SOCKS5 stream whose Close also gives up the
// receive side and any blocked write. webtransport.Stream.Close only ends the
// send side, so a stream dropped without being piped (its target could not be
// dialed) would keep the visitor's data buffered on the shared session.
type reverseStream struct{ *webtransport.Stream }

func (s reverseStream) Close() error {
	s.CancelRead(0)
	_ = s.SetWriteDeadline(time.Now())
	return s.Stream.Close()
}

// webTransportKeepAlive is how often an otherwise idle WebTransport connection
// sends a QUIC keepalive. It must stay below quic-go's default idle timeout
// (30s), or an idle tunnel is dropped and every flow through it is reset.
const webTransportKeepAlive = 15 * time.Second

// newWebTransportQUICConfig is the QUIC configuration of the WebTransport client.
// DATAGRAM and partial-delivery support are required by webtransport-go.
func newWebTransportQUICConfig() *quic.Config {
	return &quic.Config{
		EnableDatagrams:                  true,
		EnableStreamResetPartialDelivery: true,
		KeepAlivePeriod:                  webTransportKeepAlive,
	}
}

// sessionDead reports whether a cached session has ended.
// sessionReusable reports whether a cached session can carry a new stream: it
// is alive and was dialed for the server addresses that are pinned now.
func sessionReusable(s interface{ Context() context.Context }, dialedFor, now string) bool {
	return !sessionDead(s) && dialedFor == now
}

func sessionDead(s interface{ Context() context.Context }) bool {
	return s.Context().Err() != nil
}

// dialAddrs calls dial for each address addr can be reached at, in order, and
// returns the first connection that succeeds. These are the pinned server
// addresses when a full tunnel cached them (the resolver is not consulted), else
// the one address addr resolves to.
func (w *WebTransportClient) dialAddrs(ctx context.Context, addr string, dial func(*net.UDPAddr) (*quic.Conn, error)) (*quic.Conn, error) {
	targets := w.client.pinnedTargets(addr)
	if targets == nil {
		targets = []string{addr}
	}
	var errs []error
	for _, t := range targets {
		remoteAddr, err := w.client.resolveUDPAddr(ctx, t)
		if err != nil {
			errs = append(errs, fmt.Errorf("resolve WebTransport address: %w", err))
			continue
		}
		conn, err := dial(remoteAddr)
		if err == nil {
			return conn, nil
		}
		errs = append(errs, err)
		if ctx.Err() != nil {
			break
		}
	}
	return nil, errors.Join(errs...)
}

func (w *WebTransportClient) dialMarkedAddr(ctx context.Context, addr string, tlsConfig *tls.Config, quicConfig *quic.Config) (*quic.Conn, error) {
	if tlsConfig.ServerName == "" {
		// The name in addr decides SNI and verification, never the pinned IP.
		tlsConfig = tlsConfig.Clone()
		if host, _, err := net.SplitHostPort(addr); err == nil {
			tlsConfig.ServerName = host
		}
	}
	return w.dialAddrs(ctx, addr, func(remoteAddr *net.UDPAddr) (*quic.Conn, error) {
		lc := net.ListenConfig{Control: w.client.markControl()}
		packetConn, err := lc.ListenPacket(ctx, "udp", "")
		if err != nil {
			return nil, fmt.Errorf("listen for WebTransport client UDP socket: %w", err)
		}
		transport := &quic.Transport{Conn: packetConn}
		conn, err := transport.DialEarly(ctx, remoteAddr, tlsConfig, quicConfig)
		if err != nil {
			_ = transport.Close()
			return nil, err
		}
		context.AfterFunc(conn.Context(), func() {
			_ = transport.Close()
		})
		return conn, nil
	})
}
