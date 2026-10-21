package server

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"reflect"
	"sync"
	"sync/atomic"
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
	signCookie   func(protocol.JwtTunnelConfig) (string, error)
}

type tunnelListener struct {
	addr      string
	isUnix    bool
	protocol  protocol.LocalProtocol
	ln        net.Listener             // reverse TCP and Unix
	pc        net.PacketConn           // reverse UDP
	relay     net.PacketConn           // UDP relay of a reverse SOCKS5 listener, if it could be bound
	assoc     protocol.UDPAssociations // senders with an authenticated UDP association, for a relay that asks for credentials
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
	// lazy completes the upgrade of a request that was held without a reply, and
	// fills in the connection. Nil for a connection that is already upgraded.
	lazy        func(extra http.Header) error
	connMu      sync.Mutex      // guards the connection fields while lazy may still set them
	gone        <-chan struct{} // closes when the held request's client disconnects
	acquired    chan struct{}
	done        chan struct{}
	once        sync.Once
	acquireOnce sync.Once
	// pipes counts the forwarders using the connection: one from the moment it
	// is acquired until the visitor's pipe has returned. The handler that owns the
	// connection (an HTTP/2 one writes through its response writer) must not
	// return before then, however the request ended.
	pipeMu   sync.Mutex
	pipeCond *sync.Cond
	pipes    int
	aborting atomic.Bool // set by abort: the session is being cut short
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

// finish ends the entry and, when closeConn is set, closes its connection. It
// waits for an upgrade in progress (see completeUpgrade), so a connection that
// upgrade produces is closed here instead of being published after the cleanup,
// and a handler that returns after finish has no upgrade still using its
// response writer.
func (w *waitingConn) finish(closeConn bool) {
	w.once.Do(func() {
		w.connMu.Lock()
		defer w.connMu.Unlock()
		if closeConn {
			if w.aborting.Load() {
				if a, ok := w.h2Conn.(interface{ Abort() }); ok {
					a.Abort()
				}
			}
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
		w.pipeMu.Lock()
		w.pipes++
		w.pipeMu.Unlock()
		close(w.acquired)
	})
}

// abort ends the entry like finish(true), for a session that is being cut short
// (shutdown, the client went away, a peer expired). On top of closing the
// connection it interrupts an HTTP/2 write blocked on the peer's flow-control
// window, which a plain Close does not, so the forwarder can stop and the
// handler, which waits for it, can return.
func (w *waitingConn) abort() {
	w.aborting.Store(true)
	w.finish(true)
}

// endPipe says the forwarder that acquired the connection is done with it. The
// forwarder defers it right after acquiring.
func (w *waitingConn) endPipe() {
	w.pipeMu.Lock()
	w.pipes--
	if w.pipeCond != nil {
		w.pipeCond.Broadcast()
	}
	w.pipeMu.Unlock()
}

// waitPipes blocks until the forwarder, if one acquired the connection, is done.
func (w *waitingConn) waitPipes() {
	w.pipeMu.Lock()
	defer w.pipeMu.Unlock()
	if w.pipeCond == nil {
		w.pipeCond = sync.NewCond(&w.pipeMu)
	}
	for w.pipes > 0 {
		w.pipeCond.Wait()
	}
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
	if closeListener && tl.pc != nil {
		_ = tl.pc.Close()
	}
	// The relay lives and dies with the TCP listener.
	if tl.relay != nil {
		_ = tl.relay.Close()
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

// waitForUseOrTimeout holds the handler of a pooled connection until the
// connection has been used and finished, or dropped. It returns only once the
// visitor's pipe, if there was one, has returned too: finish closes the
// transport to stop it, but a handler that returned while the pipe still wrote
// through its response writer would break the HTTP server's rules.
func (m *ReverseTunnelManager) waitForUseOrTimeout(tl *tunnelListener, wait *waitingConn) {
	m.holdForUse(tl, wait)
	wait.waitPipes()
}

func (m *ReverseTunnelManager) holdForUse(tl *tunnelListener, wait *waitingConn) {
	if m.idleTimeout <= 0 {
		select {
		case <-wait.gone:
			wait.abort()
			m.purgeDoneWaiters(tl)
		case <-wait.done:
		case <-tl.quit:
			wait.abort()
		}
		return
	}

	timer := time.NewTimer(m.idleTimeout)
	defer timer.Stop()

	acquired := wait.acquired
	select {
	case <-wait.gone:
		// The client of a held request disconnected, or gave up and will send
		// the request again. Either way it no longer takes a place in the pool.
		wait.abort()
		m.purgeDoneWaiters(tl)
	case <-wait.done:
	case <-tl.quit:
		wait.abort()
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
		wait.abort()
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
	return m.acquireWaitingConnUntil(tl, nil)
}

// acquireWaitingConnUntil is acquireWaitingConn that gives up as soon as cancel
// closes, instead of waiting out the ten seconds.
func (m *ReverseTunnelManager) acquireWaitingConnUntil(tl *tunnelListener, cancel <-chan struct{}) (*waitingConn, bool) {
	if cancel != nil {
		stopWatching := make(chan struct{})
		defer close(stopWatching)
		go func() {
			select {
			case <-cancel:
				tl.queueMu.Lock()
				if tl.queueCond != nil {
					tl.queueCond.Broadcast()
				}
				tl.queueMu.Unlock()
			case <-stopWatching:
			}
		}()
	}
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
				// Check that the entry is still live and count the forwarder under
				// the entry's lock. finish takes it too, so either the entry was
				// finished before and is skipped, or the count is in place before
				// finish can wake a handler that is waiting for the pipes.
				wait.connMu.Lock()
				select {
				case <-wait.done:
					wait.connMu.Unlock()
					continue
				default:
				}
				wait.markAcquired()
				wait.connMu.Unlock()
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
		case <-cancel: // a nil channel never fires
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
	} else if claims.Protocol.ReverseUdp != nil {
		// A different key from a TCP listener on the same address.
		bindAddr = "udp:" + net.JoinHostPort(claims.Remote, fmt.Sprintf("%d", claims.Port))
		network = "udp"
	} else {
		bindAddr = net.JoinHostPort(claims.Remote, fmt.Sprintf("%d", claims.Port))
		isUnix = false
		network = "tcp"
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	tl, ok := m.listeners[bindAddr]
	if ok && !reflect.DeepEqual(tl.protocol, claims.Protocol) {
		// A listener keeps the protocol and credentials it was started with. A
		// client that comes back with other ones (a password added or changed,
		// another timeout) must not be served by the old settings. Replace an
		// idle listener; refuse while visitors are being served, rather than
		// cut them off.
		if tl.active > 0 {
			return nil, bindAddr, fmt.Errorf("a reverse listener on %s is serving visitors with a different configuration", bindAddr)
		}
		slog.Info("Reverse tunnel listener replaced: the client's settings changed", "addr", tl.addr)
		delete(m.listeners, bindAddr)
		m.closeTunnelListener(tl, true)
		ok = false
	}
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

		tl = &tunnelListener{
			addr:     bindAddr,
			isUnix:   isUnix,
			protocol: claims.Protocol,
			waitCap:  10,
			quit:     make(chan struct{}),
			lastUsed: time.Now(),
		}
		if network == "udp" {
			pc, err := lc.ListenPacket(context.Background(), "udp", net.JoinHostPort(claims.Remote, fmt.Sprintf("%d", claims.Port)))
			if err != nil {
				return nil, bindAddr, err
			}
			tl.pc = pc
		} else {
			ln, err := lc.Listen(context.Background(), network, bindAddr)
			if err != nil {
				return nil, bindAddr, err
			}
			tl.ln = ln
			if claims.Protocol.ReverseSocks5 != nil {
				// UDP ASSOCIATE needs a UDP socket at the same address. Without
				// one the listener still serves CONNECT.
				relay, err := lc.ListenPacket(context.Background(), "udp", ln.Addr().String())
				if err != nil {
					slog.Warn("Reverse SOCKS5: no UDP relay, UDP ASSOCIATE is refused", "addr", bindAddr, "err", err)
				} else {
					tl.relay = relay
				}
			}
		}
		tl.queueCond = sync.NewCond(&tl.queueMu)
		m.listeners[bindAddr] = tl
		if tl.pc != nil {
			go m.runUDPListener(tl)
		} else {
			go m.runListener(tl)
			if tl.relay != nil {
				go m.runSocks5UDPRelay(tl, tl.relay)
			}
		}
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

// gone, when set, is closed when the client goes away. A parked connection
// nothing reads would otherwise stay in the pool as a dead entry, and the next
// visitor could be given it and lose what it sent.
func (m *ReverseTunnelManager) HandleClientH2(h2Conn io.ReadWriteCloser, claims *protocol.JwtTunnelConfig, gone <-chan struct{}) {
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
		gone:     gone,
	}
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
		slog.Info("Reverse tunnel (H2): client connection added to pool", "tunnel_id", claims.ID, "addr", bindAddr)
		m.waitForUseOrTimeout(tl, wait)
		return
	}
	wait.finish(true)
}

func (m *ReverseTunnelManager) runListener(tl *tunnelListener) {
	defer func() { _ = tl.ln.Close() }()
	slog.Info("Reverse tunnel listener started", "addr", tl.addr, "bound", tl.ln.Addr().String(), "proto", getProtoName(tl.protocol))

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

	// A dynamic tunnel's visitor names its target through the front-end
	// protocol, and is told afterwards whether the connection was made.
	dynamic := tl.protocol.ReverseDynamic()
	reply := func(bool) error { return nil }
	switch {
	case tl.protocol.ReverseSocks5 != nil:
		var cmd byte
		cmd, targetHost, targetPort, err = readSocks5Command(conn, tl.protocol.ReverseSocks5.Credentials)
		if err != nil {
			slog.Warn("Reverse SOCKS5 handshake failed", "err", err)
			return
		}
		if cmd == socks5CmdUDPAssociate {
			// Datagrams go to the relay socket, not through this connection,
			// which only says how long the association lasts.
			if tl.relay == nil {
				_ = socks5Reply(conn, socks5CommandNotSupported)
				return
			}
			// Registered before the reply: the visitor may send its first
			// datagram as soon as it has read it.
			release := tl.assoc.Add(protocol.AddrIP(conn.RemoteAddr()))
			defer release()
			if err := socks5ReplyAddr(conn, socks5Succeeded, relayAddrFor(tl.relay.LocalAddr(), conn.LocalAddr())); err != nil {
				return
			}
			// The association ends with this connection, or with the listener.
			over := make(chan struct{})
			defer close(over)
			go func() {
				select {
				case <-tl.quit:
					_ = conn.Close()
				case <-over:
				}
			}()
			_, _ = io.Copy(io.Discard, conn)
			return
		}
		reply = func(ok bool) error {
			if ok {
				return socks5Reply(conn, socks5Succeeded)
			}
			return socks5Reply(conn, socks5GeneralFailure)
		}
	case tl.protocol.ReverseHttpProxy != nil:
		var v *dynamicVisitor
		v, err = readHTTPProxyRequest(conn, tl.protocol.ReverseHttpProxy.Credentials)
		if err != nil {
			slog.Warn("Reverse HTTP proxy request failed", "err", err)
			return
		}
		targetHost, targetPort, reply, conn = v.host, v.port, v.reply, v.conn
	}

	// Get a waiting client connection
	wait, ok := m.acquireWaitingConn(tl)
	if !ok {
		slog.Error("Reverse tunnel: no client available to handle connection", "addr", tl.addr)
		_ = reply(false)
		return
	}

	// The handler waits for the pipe (see waitForUseOrTimeout), so endPipe must
	// run after the finish below, and it is registered first.
	defer wait.endPipe()
	// The tunnel side of the pipe is closed when the entry ends, but a pump can
	// be stuck on the visitor instead (it stopped reading, or has nothing to
	// say), and closing the tunnel does not free that. Close the visitor too.
	releaseVisitor := make(chan struct{})
	defer close(releaseVisitor)
	go func() {
		select {
		case <-wait.done:
			_ = conn.Close()
		case <-releaseVisitor:
		}
	}()
	// A connection upgraded here, for a held request, has no handler of its own
	// to close it afterwards, so close it. One that arrived upgraded is closed by
	// the handler that received it.
	defer func() { wait.finish(wait.lazy != nil) }()
	m.touchListener(tl)

	if dynamic {
		// The client's request was held for this: answer it now, with the
		// target the visitor asked for, then tell the visitor it is connected.
		if err := m.answerHeldRequest(wait, targetHost, targetPort, false); err != nil {
			slog.Warn("Reverse tunnel: cannot hand the connection to the client", "addr", tl.addr, "err", err)
			_ = reply(false)
			wait.finish(true)
			return
		}
		if err := reply(true); err != nil {
			wait.finish(true)
			return
		}
	}

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
		if !dynamic {
			_ = wait.wsConn.WriteMessage(wst.BinaryMessage, nil)
		}
		tunnel.PipeLive(conn, wait.wsConn, live)
		stop()
	} else if wait.gorillaConn != nil {
		stop, live := tunnel.WatchGorilla(wait.gorillaConn, m.pingInterval, "addr", tl.addr)
		if !dynamic {
			_ = wait.gorillaConn.WriteMessage(websocket.BinaryMessage, nil)
		}
		tunnel.PipeGorillaLive(conn, wait.gorillaConn, live)
		stop()
	} else {
		tunnel.PipeBiDir(conn, wait.h2Conn)
	}
}

// socks5HandshakeTimeout is how long a visitor to a reverse SOCKS5 listener has
// to send its greeting and request (Rust #515). The deadline is cleared once the
// handshake is done.
var socks5HandshakeTimeout = 10 * time.Second
