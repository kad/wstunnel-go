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

	"github.com/gorilla/websocket"
	"github.com/kad/wstunnel-go/internal/socket"
	"github.com/kad/wstunnel-go/pkg/protocol"
	"github.com/kad/wstunnel-go/pkg/tunnel"
	"github.com/kad/wstunnel-go/pkg/wst"
)

type ReverseTunnelManager struct {
	listeners    map[string]*tunnelListener
	mu           sync.Mutex
	socketSoMark uint32
	idleTimeout  time.Duration
	pingInterval time.Duration
	stop         chan struct{}
	stopOnce     sync.Once
}

type tunnelListener struct {
	addr      string
	isUnix    bool
	protocol  protocol.LocalProtocol
	ln        net.Listener
	waiting   []*waitingConn
	waitCap   int
	queueMu   sync.Mutex
	queueCond *sync.Cond
	quit      chan struct{}
	quitOnce  sync.Once
	lastUsed  time.Time
	active    int
}

type waitingConn struct {
	wsConn      *wst.Conn
	gorillaConn *websocket.Conn
	h2Conn      io.ReadWriteCloser
	acquired    chan struct{}
	done        chan struct{}
	once        sync.Once
	acquireOnce sync.Once
}

func NewReverseTunnelManager(socketSoMark uint32, idleTimeout time.Duration) *ReverseTunnelManager {
	m := &ReverseTunnelManager{
		listeners:    make(map[string]*tunnelListener),
		socketSoMark: socketSoMark,
		idleTimeout:  idleTimeout,
		stop:         make(chan struct{}),
	}
	if idleTimeout > 0 {
		go m.reapIdleListeners()
	}
	return m
}

// withPingInterval enables the liveness watchdog on forwarded connections.
func (m *ReverseTunnelManager) withPingInterval(d time.Duration) *ReverseTunnelManager {
	m.pingInterval = d
	return m
}

func (m *ReverseTunnelManager) Close() {
	m.stopOnce.Do(func() {
		close(m.stop)
	})

	m.mu.Lock()
	listeners := make([]*tunnelListener, 0, len(m.listeners))
	for addr, tl := range m.listeners {
		delete(m.listeners, addr)
		listeners = append(listeners, tl)
	}
	m.mu.Unlock()

	for _, tl := range listeners {
		slog.Info("Reverse tunnel listener closed", "addr", tl.addr, "reason", "shutdown")
		m.closeTunnelListener(tl, true)
	}
}

func (w *waitingConn) finish(closeConn bool) {
	w.once.Do(func() {
		if closeConn {
			switch {
			case w.wsConn != nil:
				_ = w.wsConn.Close()
			case w.gorillaConn != nil:
				_ = w.gorillaConn.Close()
			case w.h2Conn != nil:
				_ = w.h2Conn.Close()
			}
		}
		close(w.done)
	})
}

func (w *waitingConn) markAcquired() {
	if w == nil || w.acquired == nil {
		return
	}
	w.acquireOnce.Do(func() {
		close(w.acquired)
	})
}

func (w *waitingConn) isAcquired() bool {
	if w == nil || w.acquired == nil {
		return false
	}
	select {
	case <-w.acquired:
		return true
	default:
		return false
	}
}

func (m *ReverseTunnelManager) touchListener(tl *tunnelListener) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if current, ok := m.listeners[tl.addr]; ok && current == tl {
		tl.lastUsed = time.Now()
	}
}

func (m *ReverseTunnelManager) updateActivePipes(tl *tunnelListener, delta int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if current, ok := m.listeners[tl.addr]; ok && current == tl {
		tl.active += delta
		tl.lastUsed = time.Now()
	}
}

func (m *ReverseTunnelManager) beginIncoming(tl *tunnelListener) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if current, ok := m.listeners[tl.addr]; ok && current == tl {
		tl.active++
		tl.lastUsed = time.Now()
	}
}

func (m *ReverseTunnelManager) reapIdleListeners() {
	interval := m.idleTimeout / 2
	if interval < 10*time.Millisecond {
		interval = 10 * time.Millisecond
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stop:
			return
		case <-ticker.C:
			m.reapIdleListenersOnce(time.Now())
		}
	}
}

func (m *ReverseTunnelManager) reapIdleListenersOnce(now time.Time) {
	var stale []*tunnelListener

	m.mu.Lock()
	for addr, tl := range m.listeners {
		if tl.active > 0 || now.Sub(tl.lastUsed) < m.idleTimeout {
			continue
		}
		delete(m.listeners, addr)
		stale = append(stale, tl)
	}
	m.mu.Unlock()

	for _, tl := range stale {
		slog.Info("Reverse tunnel listener closed", "addr", tl.addr, "reason", "idle", "idle_timeout", m.idleTimeout)
		m.closeTunnelListener(tl, true)
	}
}

func (m *ReverseTunnelManager) closeTunnelListener(tl *tunnelListener, closeListener bool) {
	if tl == nil {
		return
	}

	tl.queueMu.Lock()
	tl.quitOnce.Do(func() {
		close(tl.quit)
	})
	if tl.queueCond != nil {
		tl.queueCond.Broadcast()
	}
	tl.queueMu.Unlock()

	if closeListener && tl.ln != nil {
		_ = tl.ln.Close()
	}
}

// pingParked keeps a connection pinged from the moment it is accepted until it
// is used, so the client can tell a dead server from a quiet one. It starts
// before the connection is admitted to the pool: the response already promised
// pings, and a connection stuck behind a full pool would otherwise look dead.
// The client does not answer these pings (nothing here reads the connection
// while it is parked), so no replies pile up. A write that fails outright means
// the peer is gone: the slot is freed and a handler still waiting for a place in
// the pool is woken to give up.
func (m *ReverseTunnelManager) pingParked(tl *tunnelListener, wait *waitingConn) {
	if m.pingInterval <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(m.pingInterval)
		defer ticker.Stop()
		for {
			select {
			case <-wait.done:
				return
			case <-wait.acquired:
				return
			case <-tl.quit:
				return
			case <-ticker.C:
			}
			deadline := time.Now().Add(m.pingInterval)
			var err error
			switch {
			case wait.wsConn != nil:
				err = wait.wsConn.WriteControl(wst.PingMessage, nil, deadline)
			case wait.gorillaConn != nil:
				err = wait.gorillaConn.WriteControl(websocket.PingMessage, nil, deadline)
			default:
				return
			}
			// A ping that only timed out is skipped; any other error, including
			// a cached fatal socket timeout, means the connection is gone.
			if err != nil && !tunnel.IsTransientWriteTimeout(err) {
				slog.Debug("Reverse tunnel: parked client connection lost", "addr", tl.addr, "err", err)
				wait.finish(true)
				tl.queueMu.Lock()
				m.purgeDoneWaitersLocked(tl)
				if tl.queueCond != nil {
					tl.queueCond.Broadcast()
				}
				tl.queueMu.Unlock()
				return
			}
		}
	}()
}

func (m *ReverseTunnelManager) waitForUseOrTimeout(tl *tunnelListener, wait *waitingConn) {
	if m.idleTimeout <= 0 {
		select {
		case <-wait.done:
		case <-tl.quit:
			wait.finish(true)
		}
		return
	}

	timer := time.NewTimer(m.idleTimeout)
	defer timer.Stop()

	acquired := wait.acquired
	select {
	case <-wait.done:
	case <-tl.quit:
		wait.finish(true)
	case <-acquired:
		m.waitAfterAcquireOrShutdown(tl, wait)
	case <-timer.C:
		m.handleWaitTimeout(tl, wait)
	}
}

func (m *ReverseTunnelManager) waitAfterAcquireOrShutdown(tl *tunnelListener, wait *waitingConn) {
	select {
	case <-wait.done:
	case <-tl.quit:
		wait.finish(true)
	}
}

func (m *ReverseTunnelManager) handleWaitTimeout(tl *tunnelListener, wait *waitingConn) {
	if wait.isAcquired() {
		m.waitAfterAcquireOrShutdown(tl, wait)
		return
	}

	slog.Info("Reverse tunnel: closing idle client connection", "addr", tl.addr)
	wait.finish(true)
	m.purgeDoneWaiters(tl)
}

func (m *ReverseTunnelManager) purgeDoneWaitersLocked(tl *tunnelListener) {
	pending := tl.waiting[:0]
	removed := false

	for _, wait := range tl.waiting {
		if wait == nil {
			removed = true
			continue
		}
		select {
		case <-wait.done:
			removed = true
		default:
			pending = append(pending, wait)
		}
	}

	if len(pending) == 0 {
		tl.waiting = nil
	} else {
		tl.waiting = pending
	}

	if removed && tl.queueCond != nil {
		tl.queueCond.Broadcast()
	}
}

func (m *ReverseTunnelManager) purgeDoneWaiters(tl *tunnelListener) {
	tl.queueMu.Lock()
	defer tl.queueMu.Unlock()

	m.purgeDoneWaitersLocked(tl)
}

func (m *ReverseTunnelManager) enqueueWaitingConn(tl *tunnelListener, wait *waitingConn) bool {
	tl.queueMu.Lock()
	defer tl.queueMu.Unlock()

	for {
		m.purgeDoneWaitersLocked(tl)

		select {
		case <-tl.quit:
			return false
		case <-wait.done:
			return false // the client went away while waiting for a place
		default:
		}

		if len(tl.waiting) < tl.waitCap {
			tl.waiting = append(tl.waiting, wait)
			if tl.queueCond != nil {
				tl.queueCond.Broadcast()
			}
			return true
		}

		if tl.queueCond == nil {
			return false
		}
		tl.queueCond.Wait()
	}
}

func (m *ReverseTunnelManager) acquireWaitingConn(tl *tunnelListener) (*waitingConn, bool) {
	timer := time.AfterFunc(10*time.Second, func() {
		if tl.queueCond != nil {
			tl.queueMu.Lock()
			tl.queueCond.Broadcast()
			tl.queueMu.Unlock()
		}
	})
	defer timer.Stop()

	deadline := time.Now().Add(10 * time.Second)

	tl.queueMu.Lock()
	defer tl.queueMu.Unlock()

	for {
		m.purgeDoneWaitersLocked(tl)
		if len(tl.waiting) > 0 {
			wait := tl.waiting[0]
			tl.waiting = tl.waiting[1:]
			if len(tl.waiting) == 0 {
				tl.waiting = nil
			}
			if tl.queueCond != nil {
				tl.queueCond.Broadcast()
			}
			if wait != nil {
				wait.markAcquired()
				return wait, true
			}
			continue
		}

		if !time.Now().Before(deadline) {
			return nil, false
		}

		select {
		case <-tl.quit:
			return nil, false
		default:
		}

		if tl.queueCond == nil {
			return nil, false
		}
		tl.queueCond.Wait()
	}
}

func (m *ReverseTunnelManager) getOrCreateListener(claims *protocol.JwtTunnelConfig) (*tunnelListener, string, error) {
	var bindAddr string
	var isUnix bool
	var network string

	if claims.Protocol.ReverseUnix != nil {
		bindAddr = claims.Remote
		if bindAddr == "" {
			bindAddr = claims.Protocol.ReverseUnix.Path
		}
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
			waitCap:  10,
			quit:     make(chan struct{}),
			lastUsed: time.Now(),
		}
		tl.queueCond = sync.NewCond(&tl.queueMu)
		m.listeners[bindAddr] = tl
		go m.runListener(tl)
	}
	tl.lastUsed = time.Now()
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
		wsConn:   wsConn,
		acquired: make(chan struct{}),
		done:     make(chan struct{}),
	}

	m.pingParked(tl, wait)
	if m.enqueueWaitingConn(tl, wait) {
		m.touchListener(tl)
		slog.Info("Reverse tunnel: client connection added to pool", "tunnel_id", claims.ID, "addr", bindAddr)
		m.waitForUseOrTimeout(tl, wait)
		return
	}
	wait.finish(true)
}

func (m *ReverseTunnelManager) HandleGorillaClient(wsConn *websocket.Conn, claims *protocol.JwtTunnelConfig) {
	tl, bindAddr, err := m.getOrCreateListener(claims)
	if err != nil {
		slog.Error("Reverse tunnel: failed to listen", "addr", bindAddr, "err", err)
		_ = wsConn.Close()
		return
	}

	wait := &waitingConn{
		gorillaConn: wsConn,
		acquired:    make(chan struct{}),
		done:        make(chan struct{}),
	}

	m.pingParked(tl, wait)
	if m.enqueueWaitingConn(tl, wait) {
		m.touchListener(tl)
		slog.Info("Reverse tunnel (gorilla): client connection added to pool", "tunnel_id", claims.ID, "addr", bindAddr)
		m.waitForUseOrTimeout(tl, wait)
		return
	}
	wait.finish(true)
}

func (m *ReverseTunnelManager) HandleClientH2(h2Conn io.ReadWriteCloser, claims *protocol.JwtTunnelConfig) {
	tl, bindAddr, err := m.getOrCreateListener(claims)
	if err != nil {
		slog.Error("Reverse tunnel: failed to listen", "addr", bindAddr, "err", err)
		_ = h2Conn.Close()
		return
	}

	wait := &waitingConn{
		h2Conn:   h2Conn,
		acquired: make(chan struct{}),
		done:     make(chan struct{}),
	}

	if m.enqueueWaitingConn(tl, wait) {
		m.touchListener(tl)
		slog.Info("Reverse tunnel (H2): client connection added to pool", "tunnel_id", claims.ID, "addr", bindAddr)
		m.waitForUseOrTimeout(tl, wait)
		return
	}
	wait.finish(true)
}

func (m *ReverseTunnelManager) runListener(tl *tunnelListener) {
	defer func() { _ = tl.ln.Close() }()
	slog.Info("Reverse tunnel listener started", "addr", tl.addr, "proto", getProtoName(tl.protocol))

	for {
		conn, err := tl.ln.Accept()
		if err != nil {
			select {
			case <-tl.quit:
				// Closed on purpose by the reaper or shutdown, already logged.
			default:
				slog.Warn("Reverse tunnel listener error", "addr", tl.addr, "err", err)
			}
			m.closeTunnelListener(tl, false)
			m.mu.Lock()
			if current, ok := m.listeners[tl.addr]; ok && current == tl {
				delete(m.listeners, tl.addr)
			}
			m.mu.Unlock()
			return
		}

		m.beginIncoming(tl)
		go m.handleIncoming(tl, conn)
	}
}

func (m *ReverseTunnelManager) handleIncoming(tl *tunnelListener, conn net.Conn) {
	defer func() { _ = conn.Close() }()
	defer m.updateActivePipes(tl, -1)

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
	wait, ok := m.acquireWaitingConn(tl)
	if !ok {
		slog.Error("Reverse tunnel: no client available to handle connection", "addr", tl.addr)
		return
	}

	defer wait.finish(false)
	m.touchListener(tl)

	start := time.Now()
	slog.Info("Reverse tunnel: forwarding connection to client", "addr", tl.addr, "peer", conn.RemoteAddr().String(), "target_host", targetHost, "target_port", targetPort)
	defer func() {
		slog.Info("Reverse tunnel: forwarded connection closed", "addr", tl.addr, "peer", conn.RemoteAddr().String(), "duration", time.Since(start).Round(time.Millisecond))
	}()
	// The watchdog starts before the wake-up frame (which tells a Go client to
	// dial its local target now; Rust clients treat it as an empty payload).
	// The frame can block on the write lock when the parked client stopped
	// draining, and acquiring the connection ended the parked idle timeout, so
	// without a watchdog the visitor would hang on it indefinitely.
	if wait.wsConn != nil {
		stop, live := tunnel.WatchWst(wait.wsConn, m.pingInterval, "addr", tl.addr)
		_ = wait.wsConn.WriteMessage(wst.BinaryMessage, nil)
		tunnel.PipeLive(conn, wait.wsConn, live)
		stop()
	} else if wait.gorillaConn != nil {
		stop, live := tunnel.WatchGorilla(wait.gorillaConn, m.pingInterval, "addr", tl.addr)
		_ = wait.gorillaConn.WriteMessage(websocket.BinaryMessage, nil)
		tunnel.PipeGorillaLive(conn, wait.gorillaConn, live)
		stop()
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
