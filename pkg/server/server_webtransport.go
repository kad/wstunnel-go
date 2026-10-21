package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/kad/wstunnel-go/internal/socket"
	"github.com/kad/wstunnel-go/pkg/protocol"
	"github.com/kad/wstunnel-go/pkg/tun"
	"github.com/kad/wstunnel-go/pkg/tunnel"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
)

type WebTransportServer struct {
	server *Server

	// mu guards wtServer and closed: Close can run while Start is still
	// bringing the listener up (a shutdown during startup, a Caddy reload).
	mu       sync.Mutex
	wtServer *webtransport.Server
	udpConn  net.PacketConn
	served   chan struct{} // closed when wtServer.Serve has returned
	closed   bool
}

type webTransportRequest struct {
	path       string
	auth       string
	commonName string
}

const webTransportAuthTimeout = 10 * time.Second

// webTransportCloseWait bounds how long Close waits for Serve to return.
const webTransportCloseWait = 5 * time.Second

func NewWebTransportServer(server *Server) *WebTransportServer {
	return &WebTransportServer{server: server}
}

func generateDummyTLSConfig() (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"wstunnel-go webtransport"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h3"},
	}, nil
}

func (w *WebTransportServer) Start(bindAddr string, tlsConfig *tls.Config) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return errors.New("WebTransport server is closed")
	}
	if tlsConfig == nil {
		dummyConfig, err := generateDummyTLSConfig()
		if err != nil {
			return fmt.Errorf("failed to generate TLS config for WebTransport: %w", err)
		}
		tlsConfig = dummyConfig
	} else if tlsConfig.NextProtos == nil {
		tlsConfig.NextProtos = []string{"h3"}
	}

	wtServer := &webtransport.Server{
		H3: &http3.Server{
			Addr:      bindAddr,
			TLSConfig: tlsConfig,
		},
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(rw http.ResponseWriter, r *http.Request) {
		if w.server.Config.PathPrefix != "" {
			expectedPrefix := "/" + w.server.Config.PathPrefix
			if !strings.HasPrefix(r.URL.Path, expectedPrefix) {
				http.Error(rw, "Not found", http.StatusNotFound)
				return
			}
		}

		request := webTransportRequest{
			path: r.URL.Path,
			auth: r.Header.Get("Authorization"),
		}
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			request.commonName = r.TLS.PeerCertificates[0].Subject.CommonName
		}

		sess, err := wtServer.Upgrade(rw, r)
		if err != nil {
			slog.Warn("WebTransport upgrade failed", "err", err)
			return
		}
		go w.handleSession(sess, request)
	})

	wtServer.H3.Handler = mux

	var lc net.ListenConfig
	if w.server.Config.SocketSoMark != 0 {
		lc.Control = func(network, address string, rc syscall.RawConn) error {
			return rc.Control(func(fd uintptr) {
				_ = socket.SetSoMark(fd, w.server.Config.SocketSoMark)
			})
		}
	}
	udpConn, err := lc.ListenPacket(context.Background(), "udp", bindAddr)
	if err != nil {
		return fmt.Errorf("listen for WebTransport: %w", err)
	}

	served := make(chan struct{})
	go func() {
		defer close(served)
		if err := wtServer.Serve(udpConn); err != nil {
			_ = udpConn.Close()
			slog.Debug("WebTransport server stopped", "err", err)
		}
	}()

	w.wtServer = wtServer
	w.udpConn = udpConn
	w.served = served
	return nil
}

// Close stops the listener, if one was started, and keeps a later Start from
// bringing one up. It is safe to call more than once.
func (w *WebTransportServer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	if w.wtServer == nil {
		return nil
	}
	// webtransport.Server.Close races with a Serve that has only just started
	// (both touch the server's internal state). Closing the socket first makes
	// Serve return; closing the server after that is ordered behind it.
	_ = w.udpConn.Close()
	select {
	case <-w.served:
	case <-time.After(webTransportCloseWait):
		slog.Warn("WebTransport Serve did not return after its socket was closed")
	}
	return w.wtServer.Close()
}

func (w *WebTransportServer) handleSession(sess *webtransport.Session, request webTransportRequest) {
	ctx := context.Background()
	for {
		stream, err := sess.AcceptStream(ctx)
		if err != nil {
			return
		}
		go w.handleStream(stream, request)
	}
}

func (w *WebTransportServer) handleStream(stream *webtransport.Stream, request webTransportRequest) {
	defer func() { _ = stream.Close() }()

	if err := stream.SetReadDeadline(time.Now().Add(webTransportAuthTimeout)); err != nil {
		slog.Warn("WebTransport stream failed to set authentication deadline", "err", err)
		return
	}
	jwtStr, err := protocol.ReadJWTStreamPreamble(stream)
	if err != nil {
		slog.Warn("WebTransport stream failed to read JWT preamble", "err", err)
		return
	}
	if err := stream.SetReadDeadline(time.Time{}); err != nil {
		slog.Warn("WebTransport stream failed to clear authentication deadline", "err", err)
		return
	}

	claims, err := w.server.parseJWTClaims(jwtStr)
	if err != nil {
		slog.Warn("WebTransport stream invalid JWT", "err", err)
		return
	}
	normalizeTunClaims(claims)
	slog.Info("Accepted WebTransport tunnel", "id", claims.ID, "proto", getProtoName(claims.Protocol), "remote", claims.Remote, "port", claims.Port)
	defer logTunnelClosed(claims, "webtransport", time.Now())

	destAddr := claims.Remote
	destPort := claims.Port

	var rule *RestrictionConfig
	if w.server.rules != nil {
		var ok bool
		rule, ok = w.server.rules.ValidateMatch(claims, request.path, request.auth, request.commonName)
		if !ok {
			slog.Warn("WebTransport access restricted", "dest", destAddr, "port", destPort)
			return
		}
	}
	if err := w.server.admitTun(claims); err != nil {
		slog.Warn("WebTransport stream rejected", "tunnel_id", claims.ID, "err", err)
		return
	}
	if claims.Protocol.Tun != nil {
		w.server.serveTun(tun.NewFramedPacketConn(tunStream{stream}), claims, rule)
		return
	}

	// A reverse session ends from this side as well (an expired peer, a client
	// that went away), and a plain stream's Close only ends its send side, which
	// leaves the other direction of the pipe blocked. tunStream's Close aborts
	// both directions.
	var base io.ReadWriteCloser = stream
	if claims.Protocol.ReverseTcp != nil || claims.Protocol.ReverseUnix != nil ||
		claims.Protocol.ReverseUdp != nil || claims.Protocol.ReverseDynamic() {
		base = tunStream{stream}
	}
	streamRWC := base
	var udpStream *protocol.FramedUDPReadWriteCloser
	if claims.Protocol.Udp != nil || claims.Protocol.ReverseUdp != nil {
		udpStream = protocol.NewFramedUDPReadWriteCloser(base)
		streamRWC = udpStream
	}

	// Forward Tunnel
	if claims.Protocol.Tcp != nil || claims.Protocol.Udp != nil || claims.Protocol.Socks5 != nil || claims.Protocol.HttpProxy != nil || claims.Protocol.Unix != nil {
		var targetAddr string
		network := "tcp"

		if claims.Protocol.Unix != nil {
			targetAddr = claims.Protocol.Unix.Path
			network = "unix"
		} else {
			targetAddr = net.JoinHostPort(claims.Remote, fmt.Sprintf("%d", claims.Port))
			if claims.Protocol.Udp != nil {
				network = "udp"
			}
		}

		conn, err := net.DialTimeout(network, targetAddr, 10*time.Second)
		if err != nil {
			slog.Error("Failed to connect to target (WebTransport)", "network", network, "target", targetAddr, "err", err)
			return
		}
		defer func() { _ = conn.Close() }()

		if udpStream != nil {
			tunnel.PipeUDP(conn, udpStream)
			return
		}
		tunnel.PipeBiDir(conn, streamRWC)
		return
	}

	// Reverse Tunnel
	if claims.Protocol.ReverseDynamic() {
		// The target the visitor asked for reaches the client as a JWT preamble
		// on the stream, once a visitor has asked for one.
		// A stream has no request context to tell that its client gave up and
		// will ask again, so watch it: while it is held the client sends nothing,
		// and any end of the stream means it has gone.
		gone, stopWatching := watchHeldStream(stream)
		defer stopWatching()
		// A request that ends before its upgrade has no transport for finish to
		// close. Close the whole stream, receive side included, so a client that
		// keeps its send side open cannot hold the stream.
		defer func() { _ = base.Close() }()
		if err := w.server.rvMgr.HandleDynamicClient(claims, lazyUpgrade{stream: func(extra http.Header) (io.ReadWriteCloser, error) {
			stopWatching() // the pipe reads the stream from here on
			if err := writePreamble(stream, extra.Get("Cookie"), webTransportAuthTimeout); err != nil {
				return nil, err
			}
			return base, nil
		}}, gone); err != nil {
			slog.Warn("WebTransport reverse request refused", "tunnel_id", claims.ID, "err", err)
		}
		return
	}
	if claims.Protocol.ReverseTcp != nil || claims.Protocol.ReverseUnix != nil || claims.Protocol.ReverseUdp != nil {
		// Watch the client's sending half too. The framing for UDP goes over the
		// watcher so that its kept byte is read as part of the first frame.
		watched := newWatchedStream(base)
		var parked io.ReadWriteCloser = watched
		if claims.Protocol.ReverseUdp != nil {
			parked = protocol.NewFramedUDPReadWriteCloser(watched)
		}
		w.server.rvMgr.HandleClientH2(parked, claims, eitherDone(stream.Context().Done(), watched.Gone()))
		return
	}

	slog.Warn("WebTransport unsupported protocol target", "protocol", claims.Protocol)
}

// preambleStream is the part of a stream that writePreamble needs.
type preambleStream interface {
	Write([]byte) (int, error)
	SetWriteDeadline(time.Time) error
}

// writePreamble sends the target JWT on a stream under a deadline. It runs while
// the entry's lock is held, and a client that withholds flow-control credit
// would otherwise block the write, and with it every cancellation, for good.
func writePreamble(stream preambleStream, jwtStr string, timeout time.Duration) error {
	_ = stream.SetWriteDeadline(time.Now().Add(timeout))
	err := protocol.WriteJWTStreamPreamble(stream, jwtStr)
	_ = stream.SetWriteDeadline(time.Time{})
	return err
}

// heldStream is the part of a stream that watchHeldStream needs.
type heldStream interface {
	Read([]byte) (int, error)
	SetReadDeadline(time.Time) error
}

// watchHeldStream reports when the client of a held WebTransport stream ends it,
// by reading the stream, on which a held client sends nothing. stop ends the
// watching without consuming anything, and must run before the stream is read for
// anything else. It is safe to call more than once.
func watchHeldStream(stream heldStream) (gone <-chan struct{}, stop func()) {
	g := make(chan struct{})
	finished := make(chan struct{})
	var stopped atomic.Bool
	go func() {
		defer close(finished)
		var b [1]byte
		_, _ = stream.Read(b[:])
		// A held client sends nothing, so the read finishing, with data as much
		// as with an error, means the stream is no longer a held request.
		if !stopped.Load() {
			close(g)
		}
	}()
	var once sync.Once
	return g, func() {
		once.Do(func() {
			stopped.Store(true)
			_ = stream.SetReadDeadline(time.Now())
			<-finished
			_ = stream.SetReadDeadline(time.Time{})
		})
	}
}

// watchedStream watches a parked stream for the client ending its sending half
// (closed or reset), which the stream's own context does not report while the
// session lives on. A parked client normally sends nothing, but one that dials
// its target eagerly may, so the first byte read is kept and handed to whoever
// reads the stream next: the watcher never costs the pipe any data.
type watchedStream struct {
	io.ReadWriteCloser
	ready chan struct{} // closed when the watcher's read has returned
	gone  chan struct{} // closed when that read ended the stream without data
	b     [1]byte
	n     int
	err   error
	mu    sync.Mutex // guards n, which Read consumes
}

func newWatchedStream(rwc io.ReadWriteCloser) *watchedStream {
	w := &watchedStream{ReadWriteCloser: rwc, ready: make(chan struct{}), gone: make(chan struct{})}
	go func() {
		for w.n == 0 && w.err == nil {
			w.n, w.err = rwc.Read(w.b[:])
		}
		if w.n == 0 {
			close(w.gone)
		}
		close(w.ready)
	}()
	return w
}

// Gone is closed when the client ended its sending half while the stream was parked.
func (w *watchedStream) Gone() <-chan struct{} { return w.gone }

func (w *watchedStream) Read(p []byte) (int, error) {
	<-w.ready
	w.mu.Lock()
	if w.n > 0 {
		// The byte goes first; a read error that came with it is returned by
		// the next call.
		n := copy(p, w.b[:w.n])
		w.n = 0
		w.mu.Unlock()
		return n, nil
	}
	err := w.err
	w.mu.Unlock()
	if err != nil {
		return 0, err
	}
	return w.ReadWriteCloser.Read(p)
}

// eitherDone returns a channel closed when a or b is.
func eitherDone(a, b <-chan struct{}) <-chan struct{} {
	c := make(chan struct{})
	go func() {
		select {
		case <-a:
		case <-b:
		}
		close(c)
	}()
	return c
}

// tunStream adapts a WebTransport stream for tun.Serve, which closes the
// connection to unblock pumps stuck in a read or write. webtransport.Stream.Close
// only ends the send side, so also abort the receive side and any blocked write.
type tunStream struct{ *webtransport.Stream }

func (t tunStream) Close() error {
	t.CancelRead(0)
	_ = t.SetWriteDeadline(time.Now())
	return t.Stream.Close()
}
