package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"

	"github.com/kad/wstunnel-go/internal/socket"
	"github.com/kad/wstunnel-go/pkg/protocol"
	"github.com/kad/wstunnel-go/pkg/tunnel"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
)

type WebTransportServer struct {
	server   *Server
	wtServer *webtransport.Server
}

type webTransportRequest struct {
	path       string
	auth       string
	commonName string
}

const webTransportAuthTimeout = 10 * time.Second

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

	go func() {
		if err := wtServer.Serve(udpConn); err != nil {
			_ = udpConn.Close()
			slog.Debug("WebTransport server stopped", "err", err)
		}
	}()

	w.wtServer = wtServer
	return nil
}

func (w *WebTransportServer) Close() error {
	if w.wtServer != nil {
		return w.wtServer.Close()
	}
	return nil
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

	destAddr := claims.Remote
	destPort := claims.Port

	if w.server.rules != nil {
		if !w.server.rules.Validate(claims, request.path, request.auth, request.commonName) {
			slog.Warn("WebTransport access restricted", "dest", destAddr, "port", destPort)
			return
		}
	}

	var streamRWC io.ReadWriteCloser = stream
	var udpStream *protocol.FramedUDPReadWriteCloser
	if claims.Protocol.Udp != nil {
		udpStream = protocol.NewFramedUDPReadWriteCloser(stream)
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
	if claims.Protocol.ReverseTcp != nil || claims.Protocol.ReverseUnix != nil {
		w.server.rvMgr.HandleClientH2(streamRWC, claims)
		return
	}
	if claims.Protocol.ReverseUdp != nil || claims.Protocol.ReverseSocks5 != nil || claims.Protocol.ReverseHttpProxy != nil {
		slog.Warn("WebTransport unsupported reverse protocol", "protocol", claims.Protocol)
		return
	}

	slog.Warn("WebTransport unsupported protocol target", "protocol", claims.Protocol)
}
