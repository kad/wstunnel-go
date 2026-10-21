package client

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/kad/wstunnel-go/pkg/protocol"
	"github.com/kad/wstunnel-go/pkg/tunnel"
	"github.com/kad/wstunnel-go/pkg/wst"
)

// errSocks5UDPAssociate is what handleSocks5 returns for a UDP ASSOCIATE request:
// the handshake is done and the address is read, but there is no target to dial.
var errSocks5UDPAssociate = errors.New("socks5 udp associate")

// maxSocks5UDPSessions bounds the sessions one SOCKS5 UDP relay keeps.
const maxSocks5UDPSessions = 1024

// readPacket reads one datagram from the tunnel. Over HTTP/2 the tunnel is a byte
// stream, so what one read returns is the best available guess.
func (ts *tunnelStream) readPacket(buf []byte) ([]byte, error) {
	switch {
	case ts.ws != nil:
		for {
			mt, p, err := ts.ws.ReadMessage()
			if err != nil {
				return nil, err
			}
			if mt == wst.BinaryMessage {
				return p, nil
			}
		}
	case ts.gorilla != nil:
		for {
			mt, p, err := ts.gorilla.ReadMessage()
			if err != nil {
				return nil, err
			}
			if mt == websocket.BinaryMessage {
				return p, nil
			}
		}
	case ts.wt != nil:
		if pr, ok := ts.wt.(interface{ ReadPacket() ([]byte, error) }); ok {
			return pr.ReadPacket()
		}
		return nil, errors.New("webtransport stream without packets")
	case ts.h2 != nil:
		n, err := ts.h2.Read(buf)
		if n > 0 {
			return buf[:n], nil
		}
		if err == nil {
			err = io.ErrNoProgress
		}
		return nil, err
	}
	return nil, errors.New("no transport")
}

// writePacket sends one datagram into the tunnel.
func (ts *tunnelStream) writePacket(b []byte) error {
	var err error
	switch {
	case ts.ws != nil:
		err = ts.ws.WriteMessage(wst.BinaryMessage, b)
	case ts.gorilla != nil:
		err = ts.gorilla.WriteMessage(websocket.BinaryMessage, b)
	case ts.wt != nil:
		_, err = ts.wt.Write(b)
	case ts.h2 != nil:
		_, err = ts.h2.Write(b)
	default:
		err = errors.New("no transport")
	}
	return err
}

// socks5UDPQueue is how many datagrams of a session wait for its tunnel. Beyond
// that they are dropped, as UDP allows.
const socks5UDPQueue = 64

// maxSocks5UDPQueuedBytes bounds the payload one relay holds in its sessions'
// queues. The session and queue limits alone allow gigabytes, which stalled
// tunnels would turn into memory the client cannot give back.
var maxSocks5UDPQueuedBytes int64 = 16 << 20

// udpBudget counts the queued payload bytes of one relay.
type udpBudget struct{ used atomic.Int64 }

func (b *udpBudget) reserve(n int) bool {
	if b.used.Add(int64(n)) > maxSocks5UDPQueuedBytes {
		b.used.Add(-int64(n))
		return false
	}
	return true
}

func (b *udpBudget) release(n int) { b.used.Add(-int64(n)) }

// socks5UDPSession is one visitor address talking to one destination. Its worker
// opens the tunnel and sends the queued datagrams, so a slow or stalled session
// never holds up the relay's receive loop or the other sessions.
type socks5UDPSession struct {
	out      chan []byte
	budget   *udpBudget
	closed   chan struct{}
	once     sync.Once
	last     time.Time
	lastLock sync.Mutex
}

func (s *socks5UDPSession) touch() {
	s.lastLock.Lock()
	s.last = time.Now()
	s.lastLock.Unlock()
}

func (s *socks5UDPSession) idle() time.Duration {
	s.lastLock.Lock()
	defer s.lastLock.Unlock()
	return time.Since(s.last)
}

// close ends the session and gives back the bytes still queued for it.
func (s *socks5UDPSession) close() {
	s.once.Do(func() {
		close(s.closed)
		for {
			select {
			case p := <-s.out:
				s.budget.release(len(p))
			default:
				return
			}
		}
	})
}

// enqueue queues a datagram for the tunnel, unless the session is over or the
// queue or the relay's byte budget is full.
func (s *socks5UDPSession) enqueue(p []byte) {
	if isDone(s.closed) || !s.budget.reserve(len(p)) {
		return
	}
	select {
	case s.out <- p:
	default:
		s.budget.release(len(p))
	}
	// close may have drained just before this send; if so, drain what it missed.
	if isDone(s.closed) {
		for {
			select {
			case q := <-s.out:
				s.budget.release(len(q))
			default:
				return
			}
		}
	}
}

func isDone(c <-chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}

// socks5Relay holds the sessions of one SOCKS5 UDP relay.
type socks5Relay struct {
	// assoc, when set, limits the relay to senders with an authenticated UDP
	// association (a listener with credentials). Nil serves anyone.
	assoc    *protocol.UDPAssociations
	mu       sync.Mutex
	budget   udpBudget
	sessions map[string]*socks5UDPSession
}

func (r *socks5Relay) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sessions)
}

// runSocks5UDPRelay relays the UDP side of a SOCKS5 listener, as Rust's does: a
// UDP socket at the listener's address receives datagrams in the SOCKS5 UDP
// header, and each pair of visitor address and destination gets its own UDP
// tunnel to the server, which sends to the destination. What comes back is
// wrapped in the header and sent to the visitor. Datagrams are not tied to the
// TCP connection that asked for the association.
func (c *Client) runSocks5UDPRelay(pc net.PacketConn, timeout time.Duration, assoc *protocol.UDPAssociations) {
	c.serveSocks5UDPRelay(&socks5Relay{assoc: assoc, sessions: make(map[string]*socks5UDPSession)}, pc, timeout)
}

func (c *Client) serveSocks5UDPRelay(r *socks5Relay, pc net.PacketConn, timeout time.Duration) {
	defer func() { _ = pc.Close() }()
	slog.Info("SOCKS5 UDP relay started", "local", pc.LocalAddr().String())

	defer func() {
		r.mu.Lock()
		for _, s := range r.sessions {
			s.close()
		}
		r.mu.Unlock()
	}()

	buf := make([]byte, 64*1024)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		if r.assoc != nil && !r.assoc.Allows(protocol.AddrIP(from)) {
			slog.Debug("SOCKS5 UDP relay: dropping datagram from a sender without an association", "from", from.String())
			continue
		}
		host, port, hdrLen, err := protocol.ParseSocks5UDP(buf[:n])
		if err != nil {
			slog.Debug("SOCKS5 UDP relay: skipping invalid request", "from", from.String(), "err", err)
			continue
		}
		key := from.String() + "|" + net.JoinHostPort(host, strconv.Itoa(int(port)))

		r.mu.Lock()
		s, ok := r.sessions[key]
		if !ok {
			if len(r.sessions) >= maxSocks5UDPSessions {
				r.mu.Unlock()
				slog.Debug("SOCKS5 UDP relay: too many sessions, dropping datagram", "from", from.String())
				continue
			}
			s = &socks5UDPSession{out: make(chan []byte, socks5UDPQueue), budget: &r.budget, closed: make(chan struct{}), last: time.Now()}
			r.sessions[key] = s
			slog.Debug("SOCKS5 UDP relay: new session", "from", from.String(), "dest", host, "port", port)
			go func() {
				c.serveSocks5UDPSession(pc, s, from, host, port, timeout)
				r.mu.Lock()
				if r.sessions[key] == s {
					delete(r.sessions, key)
				}
				r.mu.Unlock()
			}()
		}
		r.mu.Unlock()

		s.touch()
		s.enqueue(append([]byte(nil), buf[hdrLen:n]...))
	}
}

// serveSocks5UDPSession opens the session's tunnel, sends the datagrams queued
// for it and relays the answers to the visitor until the tunnel ends, the
// session has been silent for timeout (never when it is zero), or it is closed.
func (c *Client) serveSocks5UDPSession(pc net.PacketConn, s *socks5UDPSession, to net.Addr, host string, port uint16, timeout time.Duration) {
	defer s.close()

	// Expiry runs from the moment the session exists, so a tunnel that is slow
	// to open cannot hold its slot or its queue past the timeout.
	if timeout > 0 {
		go func() {
			tick := time.NewTicker(max(timeout/4, 10*time.Millisecond))
			defer tick.Stop()
			for {
				select {
				case <-s.closed:
					return
				case <-tick.C:
					if s.idle() >= timeout {
						s.close()
						return
					}
				}
			}
		}()
	}

	udp := &protocol.UdpProtocol{}
	if timeout > 0 {
		udp.Timeout = &protocol.Duration{Secs: uint64(timeout / time.Second), Nanos: uint32(timeout % time.Second)}
	}
	// The session ending cancels opening the tunnel, which then fails, or
	// succeeds just before and is closed with the session.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-s.closed
		cancel()
	}()
	ts := c.connectToTransportContext(ctx, protocol.LocalProtocol{Udp: udp}, host, port)
	if isDone(s.closed) {
		if ts.err == nil {
			ts.Close()
		}
		return
	}
	if ts.err != nil {
		slog.Error("Failed to connect to transport for SOCKS5 UDP", "dest", net.JoinHostPort(host, strconv.Itoa(int(port))), "err", ts.err)
		return
	}
	defer ts.Close()
	// Closing the session ends the reads below.
	go func() {
		<-s.closed
		ts.Close()
	}()

	// A WebSocket tunnel is pinged, and closed when the server stays silent for
	// three intervals, like any other tunnel. Without it a sender that keeps
	// sending would keep a session on a dead tunnel alive; with it the session
	// ends and the next datagram opens a new one. Frames show life on the custom
	// websocket by themselves; for gorilla the data read below is reported.
	var live *tunnel.Liveness
	switch {
	case ts.ws != nil:
		var stop func()
		stop, live = tunnel.WatchWst(ts.ws, c.Config.PingFrequency, "role", "client")
		defer stop()
	case ts.gorilla != nil:
		var stop func()
		stop, live = tunnel.WatchGorilla(ts.gorilla, c.Config.PingFrequency, "role", "client")
		defer stop()
	}

	// Datagrams to the destination.
	go func() {
		defer s.close()
		for {
			select {
			case <-s.closed:
				return
			case p := <-s.out:
				s.budget.release(len(p))
				if err := ts.writePacket(p); err != nil {
					slog.Debug("SOCKS5 UDP relay: write to the tunnel failed", "err", err)
					return
				}
			}
		}
	}()

	// Answers from it, in the header of the destination.
	hdr := protocol.Socks5UDPHeader(host, port)
	buf := make([]byte, 64*1024)
	for {
		p, err := ts.readPacket(buf)
		if err != nil {
			return
		}
		live.Touch()
		s.touch()
		out := make([]byte, 0, len(hdr)+len(p))
		out = append(append(out, hdr...), p...)
		if _, err := pc.WriteTo(out, to); err != nil {
			return
		}
	}
}

// socks5UDPReplyAddr answers a UDP ASSOCIATE with the relay's address. A relay
// bound to every address is reached at the address the visitor used for the
// TCP connection.
func socks5UDPReplyAddr(conn net.Conn, relay net.Addr) error {
	ua, ok := relay.(*net.UDPAddr)
	if !ok {
		return errors.New("relay is not a UDP socket")
	}
	ip := ua.IP
	if ip.IsUnspecified() {
		if t, ok := conn.LocalAddr().(*net.TCPAddr); ok {
			ip = t.IP
		}
	}
	reply := []byte{0x05, 0x00, 0x00}
	if ip4 := ip.To4(); ip4 != nil {
		reply = append(reply, 0x01)
		reply = append(reply, ip4...)
	} else {
		reply = append(reply, 0x04)
		reply = append(reply, ip.To16()...)
	}
	reply = binary.BigEndian.AppendUint16(reply, uint16(ua.Port))
	_, err := conn.Write(reply)
	return err
}
