package server

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/kad/wstunnel-go/internal/socket"
	"github.com/kad/wstunnel-go/pkg/protocol"
	"github.com/kad/wstunnel-go/pkg/tunnel"
	"github.com/kad/wstunnel-go/pkg/wst"
)

type ReverseTunnelManager struct {
	listeners    map[string]*tunnelListener
	mu           sync.Mutex
	socketSoMark uint32
}

type tunnelListener struct {
	addr     string
	isUnix   bool
	protocol protocol.LocalProtocol
	ln       net.Listener
	waiting  chan *waitingConn
	quit     chan struct{}
}

type waitingConn struct {
	wsConn *wst.Conn
	h2Conn io.ReadWriteCloser
	done   chan struct{}
}

func NewReverseTunnelManager(socketSoMark uint32) *ReverseTunnelManager {
	return &ReverseTunnelManager{
		listeners:    make(map[string]*tunnelListener),
		socketSoMark: socketSoMark,
	}
}

func (m *ReverseTunnelManager) getOrCreateListener(claims *protocol.JwtTunnelConfig) (*tunnelListener, string, error) {
	var bindAddr string
	var isUnix bool
	var network string

	if claims.Protocol.ReverseUnix != nil {
		bindAddr = claims.Protocol.ReverseUnix.Path
		isUnix = true
		network = "unix"
	} else {
		bindAddr = net.JoinHostPort(claims.Remote, fmt.Sprintf("%d", claims.Port))
		isUnix = false
		network = "tcp"
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	tl, ok := m.listeners[bindAddr]
	if !ok {
		// Start new listener
		var lc net.ListenConfig
		if m.socketSoMark != 0 {
			lc.Control = func(network, address string, c syscall.RawConn) error {
				return c.Control(func(fd uintptr) {
					_ = socket.SetSoMark(fd, m.socketSoMark)
				})
			}
		}

		ln, err := lc.Listen(context.Background(), network, bindAddr)
		if err != nil {
			return nil, bindAddr, err
		}
		tl = &tunnelListener{
			addr:     bindAddr,
			isUnix:   isUnix,
			protocol: claims.Protocol,
			ln:       ln,
			waiting:  make(chan *waitingConn, 10),
			quit:     make(chan struct{}),
		}
		m.listeners[bindAddr] = tl
		go m.runListener(tl)
	}
	return tl, bindAddr, nil
}

func (m *ReverseTunnelManager) HandleClient(wsConn *wst.Conn, claims *protocol.JwtTunnelConfig) {
	tl, bindAddr, err := m.getOrCreateListener(claims)
	if err != nil {
		slog.Error("Reverse tunnel: failed to listen", "addr", bindAddr, "err", err)
		_ = wsConn.Close()
		return
	}

	wait := &waitingConn{
		wsConn: wsConn,
		done:   make(chan struct{}),
	}

	select {
	case tl.waiting <- wait:
		slog.Info("Reverse tunnel: client connection added to pool", "tunnel_id", claims.ID, "addr", bindAddr)
		<-wait.done
	case <-tl.quit:
		_ = wsConn.Close()
	}
}

func (m *ReverseTunnelManager) HandleClientH2(h2Conn io.ReadWriteCloser, claims *protocol.JwtTunnelConfig) {
	tl, bindAddr, err := m.getOrCreateListener(claims)
	if err != nil {
		slog.Error("Reverse tunnel: failed to listen", "addr", bindAddr, "err", err)
		_ = h2Conn.Close()
		return
	}

	wait := &waitingConn{
		h2Conn: h2Conn,
		done:   make(chan struct{}),
	}

	select {
	case tl.waiting <- wait:
		slog.Info("Reverse tunnel (H2): client connection added to pool", "tunnel_id", claims.ID, "addr", bindAddr)
		<-wait.done
	case <-tl.quit:
		_ = h2Conn.Close()
	}
}

func (m *ReverseTunnelManager) runListener(tl *tunnelListener) {
	defer func() { _ = tl.ln.Close() }()
	slog.Info("Reverse tunnel listener started", "addr", tl.addr, "proto", tl.protocol)

	for {
		conn, err := tl.ln.Accept()
		if err != nil {
			slog.Warn("Reverse tunnel listener error", "addr", tl.addr, "err", err)
			close(tl.quit)
			return
		}

		go m.handleIncoming(tl, conn)
	}
}

func (m *ReverseTunnelManager) handleIncoming(tl *tunnelListener, conn net.Conn) {
	defer func() { _ = conn.Close() }()

	var targetHost string
	var targetPort uint16
	var err error

	if tl.protocol.ReverseSocks5 != nil {
		targetHost, targetPort, err = m.handleSocks5Handshake(conn)
		if err != nil {
			slog.Warn("Reverse SOCKS5 handshake failed", "err", err)
			return
		}
	}

	// Get a waiting client connection
	var wait *waitingConn
	select {
	case wait = <-tl.waiting:
	case <-time.After(10 * time.Second):
		slog.Error("Reverse tunnel: no client available to handle connection", "addr", tl.addr)
		return
	}

	defer close(wait.done)

	slog.Info("Reverse tunnel: forwarding connection to client", "addr", tl.addr, "target_host", targetHost, "target_port", targetPort)
	if wait.wsConn != nil {
		tunnel.Pipe(conn, wait.wsConn)
	} else {
		tunnel.PipeBiDir(conn, wait.h2Conn)
	}
}

func (m *ReverseTunnelManager) handleSocks5Handshake(conn net.Conn) (string, uint16, error) {
	buf := make([]byte, 256)

	// 1. Version/Methods
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return "", 0, err
	}
	if buf[0] != 0x05 {
		return "", 0, fmt.Errorf("invalid socks version: %d", buf[0])
	}
	nmethods := int(buf[1])
	if _, err := io.ReadFull(conn, buf[:nmethods]); err != nil {
		return "", 0, err
	}
	// Respond: No Authentication Required
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return "", 0, err
	}

	// 2. Request
	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return "", 0, err
	}
	if buf[0] != 0x05 || buf[1] != 0x01 { // Only CONNECT supported
		return "", 0, fmt.Errorf("unsupported socks command: %d", buf[1])
	}

	var host string
	switch buf[3] {
	case 0x01: // IPv4
		if _, err := io.ReadFull(conn, buf[:4]); err != nil {
			return "", 0, err
		}
		host = net.IP(buf[:4]).String()
	case 0x03: // Domain
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return "", 0, err
		}
		sz := int(buf[0])
		if _, err := io.ReadFull(conn, buf[:sz]); err != nil {
			return "", 0, err
		}
		host = string(buf[:sz])
	case 0x04: // IPv6
		if _, err := io.ReadFull(conn, buf[:16]); err != nil {
			return "", 0, err
		}
		host = net.IP(buf[:16]).String()
	default:
		return "", 0, fmt.Errorf("unsupported address type: %d", buf[3])
	}

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return "", 0, err
	}
	port := binary.BigEndian.Uint16(buf[:2])

	// 3. Respond Success
	resp := []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(resp); err != nil {
		return "", 0, err
	}

	return host, port, nil
}
