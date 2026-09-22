package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"syscall"

	"github.com/google/uuid"
	"github.com/kad/wstunnel-go/internal/socket"
	"github.com/kad/wstunnel-go/pkg/protocol"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/webtransport-go"
)

type WebTransportClient struct {
	client *Client
	mu     sync.Mutex
	sess   *webtransport.Session
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
		}
		if w.client.Config.SocketSoMark != 0 {
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
	if p.Udp != nil {
		rwc = protocol.NewFramedUDPReadWriteCloser(stream)
	}

	return rwc, nil, nil
}

func (w *WebTransportClient) dialMarkedAddr(ctx context.Context, addr string, tlsConfig *tls.Config, quicConfig *quic.Config) (*quic.Conn, error) {
	remoteAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("resolve WebTransport address: %w", err)
	}

	var lc net.ListenConfig
	lc.Control = func(network, address string, rc syscall.RawConn) error {
		return rc.Control(func(fd uintptr) {
			_ = socket.SetSoMark(fd, w.client.Config.SocketSoMark)
		})
	}
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
}
