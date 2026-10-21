package server

import (
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kad/wstunnel-go/pkg/protocol"
	"github.com/kad/wstunnel-go/pkg/tunnel"
)

// A reverse UDP listener hands every UDP peer to a parked client connection, the
// way a reverse TCP listener hands over every accepted connection. The peer is
// identified by its source address; it keeps its client until it has been silent
// for the tunnel's timeout. One websocket message carries one datagram.

// udpPeerQueue is how many datagrams from a peer wait for a client to be
// assigned. Beyond that they are dropped, as UDP allows.
const udpPeerQueue = 64

// maxUDPDatagram is the largest UDP payload there is.
const maxUDPDatagram = 65535

// maxUDPPeers bounds the sessions one reverse UDP listener keeps at once. Source
// addresses are free to forge, and every session holds a queue, goroutines and,
// while it waits, a place in the line for a client connection. Datagrams from a
// new peer beyond the limit are dropped; admitted peers carry on.
var maxUDPPeers = 1024

// maxUDPQueuedBytes bounds the payload one reverse UDP listener holds in its
// peers' queues. The peer and queue limits alone allow gigabytes, which a
// stalled or missing client turns into memory the server cannot give back.
var maxUDPQueuedBytes int64 = 16 << 20

// udpBudget counts the queued payload bytes of one listener.
type udpBudget struct{ used atomic.Int64 }

func (b *udpBudget) reserve(n int) bool {
	if b.used.Add(int64(n)) > maxUDPQueuedBytes {
		b.used.Add(-int64(n))
		return false
	}
	return true
}

func (b *udpBudget) release(n int) { b.used.Add(-int64(n)) }

// udpPeer is one remote UDP endpoint of a reverse listener, presented as a
// net.Conn whose reads return the peer's datagrams and whose writes send a
// datagram back to it. It is what the tunnel pipe copies to and from the client.
type udpPeer struct {
	pc     net.PacketConn
	addr   net.Addr
	budget *udpBudget
	in     chan []byte
	closed chan struct{}
	once   sync.Once
	mu     sync.Mutex   // orders deliver against Close, so no datagram is queued after the drain
	last   atomic.Int64 // unix nanoseconds of the last datagram in either direction
}

func newUDPPeer(pc net.PacketConn, addr net.Addr, budget *udpBudget) *udpPeer {
	p := &udpPeer{pc: pc, addr: addr, budget: budget, in: make(chan []byte, udpPeerQueue), closed: make(chan struct{})}
	p.touch()
	return p
}

func (p *udpPeer) touch() { p.last.Store(time.Now().UnixNano()) }

// deliver queues a datagram from the peer, dropping it when the queue is full
// or the listener's byte budget is spent. A dropped datagram still shows the
// peer is sending, so it counts as activity: a tunnel that has stopped draining
// must not make a peer look silent.
func (p *udpPeer) deliver(b []byte) {
	p.touch()
	p.mu.Lock()
	defer p.mu.Unlock()
	if isClosed(p.closed) || !p.budget.reserve(len(b)) {
		return
	}
	select {
	case p.in <- b:
	default:
		p.budget.release(len(b))
	}
}

func (p *udpPeer) Read(b []byte) (int, error) {
	// A closed peer delivers nothing more, not even datagrams still queued: they
	// are older than the end of the session.
	select {
	case <-p.closed:
		return 0, io.EOF
	default:
	}
	select {
	case d := <-p.in:
		p.budget.release(len(d))
		return copy(b, d), nil
	case <-p.closed:
		return 0, io.EOF
	}
}

func (p *udpPeer) Write(b []byte) (int, error) {
	select {
	case <-p.closed:
		return 0, net.ErrClosed
	default:
	}
	p.touch()
	return p.pc.WriteTo(b, p.addr)
}

func (p *udpPeer) Close() error {
	p.once.Do(func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		close(p.closed)
		// Datagrams still queued are never read; give their bytes back.
		for {
			select {
			case d := <-p.in:
				p.budget.release(len(d))
			default:
				return
			}
		}
	})
	return nil
}

// DatagramWrites marks the peer as a destination where each Write is one
// datagram, so a message is never split across writes.
func (p *udpPeer) DatagramWrites() {}

func (p *udpPeer) LocalAddr() net.Addr              { return p.pc.LocalAddr() }
func (p *udpPeer) RemoteAddr() net.Addr             { return p.addr }
func (p *udpPeer) SetDeadline(time.Time) error      { return nil }
func (p *udpPeer) SetReadDeadline(time.Time) error  { return nil }
func (p *udpPeer) SetWriteDeadline(time.Time) error { return nil }
func (p *udpPeer) idle(now time.Time) time.Duration { return now.Sub(time.Unix(0, p.last.Load())) }

func isClosed(c <-chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}

// runUDPListener reads the reverse listener's socket and routes datagrams to the
// session of their source address, starting one for a new peer.
func (m *ReverseTunnelManager) runUDPListener(tl *tunnelListener) {
	defer func() { _ = tl.pc.Close() }()
	slog.Info("Reverse tunnel listener started", "addr", tl.addr, "bound", tl.pc.LocalAddr().String(), "proto", getProtoName(tl.protocol))

	var mu sync.Mutex
	peers := make(map[string]*udpPeer)
	var budget udpBudget
	// How long a peer may stay silent before its session ends. The client sends
	// its choice (30 seconds unless it was told otherwise), and no timeout, or a
	// zero one, means the sessions never expire, as in Rust.
	var timeout time.Duration
	if d := tl.protocol.ReverseUdp.Timeout; d != nil {
		timeout = time.Duration(d.Secs)*time.Second + time.Duration(d.Nanos)
	}

	buf := make([]byte, 64*1024)
	for {
		n, addr, err := tl.pc.ReadFrom(buf)
		if err != nil {
			select {
			case <-tl.quit:
			default:
				slog.Warn("Reverse tunnel listener error", "addr", tl.addr, "err", err)
			}
			mu.Lock()
			for _, p := range peers {
				_ = p.Close()
			}
			mu.Unlock()
			m.closeTunnelListener(tl, false)
			m.mu.Lock()
			if current, ok := m.listeners[tl.addr]; ok && current == tl {
				delete(m.listeners, tl.addr)
			}
			m.mu.Unlock()
			return
		}

		key := addr.String()
		mu.Lock()
		p, ok := peers[key]
		if !ok && len(peers) >= maxUDPPeers {
			mu.Unlock()
			slog.Debug("Reverse tunnel: too many UDP peers, dropping datagram", "addr", tl.addr, "peer", key, "limit", maxUDPPeers)
			continue
		}
		if !ok {
			slog.Debug("Reverse tunnel: new UDP peer", "addr", tl.addr, "peer", key)
			p = newUDPPeer(tl.pc, addr, &budget)
			peers[key] = p
			m.beginIncoming(tl)
			go func() {
				m.serveUDPPeer(tl, p, timeout)
				mu.Lock()
				if peers[key] == p {
					delete(peers, key)
				}
				mu.Unlock()
			}()
		}
		mu.Unlock()
		p.deliver(append([]byte(nil), buf[:n]...))
	}
}

// serveUDPPeer gives a peer a parked client connection and pipes datagrams
// between them until either side ends or the peer has been silent for timeout.
func (m *ReverseTunnelManager) serveUDPPeer(tl *tunnelListener, p *udpPeer, timeout time.Duration) {
	defer m.updateActivePipes(tl, -1)
	defer func() { _ = p.Close() }()

	// The peer's idle time runs from the moment it appeared, not from when a
	// client turned up: with no client parked, acquiring waits up to ten seconds,
	// and a peer that has already been silent for its timeout must not then be
	// served. Expiry cancels that wait, and once a client is assigned it also
	// aborts the transport.
	var assigned atomic.Pointer[waitingConn]
	expired := make(chan struct{})
	done := make(chan struct{})
	defer close(done)
	if timeout > 0 {
		go func() {
			tick := time.NewTicker(max(timeout/4, 10*time.Millisecond))
			defer tick.Stop()
			for {
				select {
				case <-done:
					return
				case now := <-tick.C:
					if p.idle(now) >= timeout {
						slog.Debug("Reverse tunnel: UDP peer idle", "peer", p.addr.String(), "timeout", timeout)
						_ = p.Close()
						close(expired)
						// Closing the peer ends the datagram side of the pipe only. A
						// client that ignores the close frame, or a stream that closes
						// only its send side, would keep the other side blocked, and
						// the expired peer with it. Close the transport too.
						if w := assigned.Load(); w != nil {
							w.abort()
						}
						return
					}
				}
			}
		}()
	}

	var cancel <-chan struct{}
	if timeout > 0 {
		cancel = expired
	}
	wait, ok := m.acquireWaitingConnUntil(tl, cancel)
	if !ok {
		if timeout > 0 && isClosed(expired) {
			slog.Debug("Reverse tunnel: UDP peer expired before a client was available", "addr", tl.addr, "peer", p.addr.String())
		} else {
			slog.Error("Reverse tunnel: no client available to handle UDP peer", "addr", tl.addr, "peer", p.addr.String())
		}
		return
	}
	defer wait.endPipe() // after the finish below; see waitForUseOrTimeout
	defer wait.finish(false)
	assigned.Store(wait)
	if isClosed(expired) { // it ran out between acquiring and now
		wait.abort()
		return
	}
	m.touchListener(tl)

	start := time.Now()
	slog.Info("Reverse tunnel: forwarding UDP peer to client", "addr", tl.addr, "peer", p.addr.String())
	defer func() {
		slog.Info("Reverse tunnel: UDP peer closed", "addr", tl.addr, "peer", p.addr.String(), "duration", time.Since(start).Round(time.Millisecond))
	}()

	// A datagram is at most 64 KiB. Without a limit a client could send one
	// message of any size, and the pipe would read it all before WriteTo could
	// refuse it.
	switch {
	case wait.wsConn != nil:
		wait.wsConn.SetReadLimit(maxUDPDatagram)
		stop, live := tunnel.WatchWst(wait.wsConn, m.pingInterval, "addr", tl.addr)
		tunnel.PipeLive(p, wait.wsConn, live)
		stop()
	case wait.gorillaConn != nil:
		wait.gorillaConn.SetReadLimit(maxUDPDatagram)
		stop, live := tunnel.WatchGorilla(wait.gorillaConn, m.pingInterval, "addr", tl.addr)
		tunnel.PipeGorillaLive(p, wait.gorillaConn, live)
		stop()
	default:
		if framed, ok := wait.h2Conn.(*protocol.FramedUDPReadWriteCloser); ok {
			tunnel.PipeUDP(p, framed)
		} else {
			tunnel.PipeBiDir(p, wait.h2Conn)
		}
	}
}

var _ net.Conn = (*udpPeer)(nil)
