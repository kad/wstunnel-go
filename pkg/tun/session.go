package tun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/kad/wstunnel-go/pkg/tun/internal/netstackutil"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Defaults applied by Serve to zero-valued Options fields.
const (
	DefaultMTU            = 1500
	MinMTU                = 1280
	DefaultDialTimeout    = 10 * time.Second
	DefaultUDPIdleTimeout = 30 * time.Second
	DefaultMaxInFlightSYN = 1024
	DefaultMaxFlows       = 4096
)

// Flow is one TCP connection or UDP association opened by the tun client.
type Flow struct {
	Network string // "tcp" or "udp"
	Src     netip.AddrPort
	Dst     netip.AddrPort
}

// Options configures a server-side tun session.
type Options struct {
	// MTU of the session NIC; must match the client's TUN MTU.
	MTU uint32
	// Authorize decides whether a new flow may be forwarded. Required.
	Authorize func(Flow) bool
	// Dial opens the outbound connection for an authorized flow.
	// Defaults to a net.Dialer.
	Dial           func(ctx context.Context, network, addr string) (net.Conn, error)
	DialTimeout    time.Duration
	UDPIdleTimeout time.Duration
	MaxInFlightSYN int
	MaxFlows       int
	Logger         *slog.Logger
}

func (o Options) withDefaults() (Options, error) {
	if o.Authorize == nil {
		return o, errors.New("tun: Options.Authorize is required")
	}
	if o.MTU == 0 {
		o.MTU = DefaultMTU
	}
	if o.MTU < MinMTU || o.MTU > MaxPacketSize {
		return o, fmt.Errorf("tun: MTU %d outside %d..%d", o.MTU, MinMTU, MaxPacketSize)
	}
	if o.Dial == nil {
		var d net.Dialer
		o.Dial = d.DialContext
	}
	if o.DialTimeout == 0 {
		o.DialTimeout = DefaultDialTimeout
	}
	if o.UDPIdleTimeout == 0 {
		o.UDPIdleTimeout = DefaultUDPIdleTimeout
	}
	if o.MaxInFlightSYN == 0 {
		o.MaxInFlightSYN = DefaultMaxInFlightSYN
	}
	if o.MaxFlows == 0 {
		o.MaxFlows = DefaultMaxFlows
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	return o, nil
}

type session struct {
	ctx   context.Context
	opts  Options
	log   *slog.Logger
	slots chan struct{}
}

// Serve terminates the IP packets carried by pc in a fresh userspace stack and
// forwards each authorized TCP/UDP flow through opts.Dial. It returns when pc
// fails, the peer disconnects, or ctx ends, and it closes pc before returning.
// A clean disconnect returns nil.
func Serve(ctx context.Context, pc PacketConn, opts Options) error {
	defer func() { _ = pc.Close() }()

	opts, err := opts.withDefaults()
	if err != nil {
		return err
	}
	s, ep, err := netstackutil.NewStack(opts.MTU)
	if err != nil {
		return err
	}
	stackOwned := false // true once Serve's teardown path owns closing s
	defer func() {
		if !stackOwned {
			s.Close()
		}
	}()

	// Accept packets from any source to any destination: every client may use
	// the same inside address, and replies go back to whatever source it used.
	if terr := s.SetPromiscuousMode(netstackutil.NICID, true); terr != nil {
		return fmt.Errorf("tun: promiscuous mode: %s", terr)
	}
	if terr := s.SetSpoofing(netstackutil.NICID, true); terr != nil {
		return fmt.Errorf("tun: spoofing: %s", terr)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	sess := &session{
		ctx:   ctx,
		opts:  opts,
		log:   opts.Logger,
		slots: make(chan struct{}, opts.MaxFlows),
	}

	tcpFwd := tcp.NewForwarder(s, 0, opts.MaxInFlightSYN, sess.handleTCP)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)
	udpFwd := udp.NewForwarder(s, sess.handleUDP)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	errc := make(chan error, 2)
	go func() { errc <- netstackutil.PumpOut(ctx, ep, pc.WritePacket) }()
	go func() { errc <- netstackutil.PumpIn(pc.ReadPacket, ep) }()

	pumps := 2
	select {
	case err = <-errc:
		pumps--
	case <-ctx.Done():
		err = nil
	}
	// Teardown order matters. cancel tears down every flow via
	// context.AfterFunc and wakes PumpOut; closing pc unblocks a pump stuck
	// in a transport read or write. Serve must not return (so the transport
	// handler must not finish) while a pump can still touch pc or the stack,
	// hence the wait before closing the stack.
	cancel()
	_ = pc.Close()
	for ; pumps > 0; pumps-- {
		<-errc
	}
	stackOwned = true
	s.Close()
	if isClosedErr(err) {
		return nil
	}
	return err
}

// isClosedErr reports whether err only says that the peer or the local side
// went away, as opposed to a genuine failure.
func isClosedErr(err error) bool {
	if err == nil {
		return true
	}
	var ce *websocket.CloseError
	return errors.As(err, &ce) ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, io.ErrClosedPipe) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, websocket.ErrCloseSent) ||
		errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.ECONNRESET)
}

// admit authorizes f and takes a flow slot. The caller must call release once
// the flow ends if admit returns true.
func (s *session) admit(f Flow) bool {
	if !s.opts.Authorize(f) {
		s.log.Info("tun flow denied", "network", f.Network, "src", f.Src, "dst", f.Dst)
		return false
	}
	select {
	case s.slots <- struct{}{}:
		return true
	default:
		s.log.Warn("tun flow limit reached", "network", f.Network, "dst", f.Dst, "max_flows", s.opts.MaxFlows)
		return false
	}
}

func (s *session) release() { <-s.slots }

func (s *session) dial(network string, dst netip.AddrPort) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(s.ctx, s.opts.DialTimeout)
	defer cancel()
	return s.opts.Dial(ctx, network, dst.String())
}

// handleTCP runs in its own goroutine per SYN (started by the forwarder). It
// dials before completing the inner handshake, so a refused or unreachable
// destination shows up to the client as a reset rather than a hang.
func (s *session) handleTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	f := Flow{
		Network: "tcp",
		Src:     netstackutil.AddrPort(id.RemoteAddress, id.RemotePort),
		Dst:     netstackutil.AddrPort(id.LocalAddress, id.LocalPort),
	}
	if !s.admit(f) {
		r.Complete(true)
		return
	}
	out, err := s.dial("tcp", f.Dst)
	if err != nil {
		s.log.Debug("tun tcp dial failed", "dst", f.Dst, "err", err)
		s.release()
		r.Complete(true)
		return
	}
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		s.log.Debug("tun tcp endpoint failed", "dst", f.Dst, "err", terr)
		_ = out.Close()
		s.release()
		r.Complete(true)
		return
	}
	r.Complete(false)
	in := gonet.NewTCPConn(&wq, ep)
	go func() {
		defer s.release()
		s.pipeTCP(in, out)
	}()
}

func (s *session) pipeTCP(in, out net.Conn) {
	stop := context.AfterFunc(s.ctx, func() {
		_ = in.Close()
		_ = out.Close()
	})
	defer stop()
	defer func() {
		_ = in.Close()
		_ = out.Close()
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(out, in)
		closeWrite(out)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(in, out)
		closeWrite(in)
	}()
	wg.Wait()
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}

// handleUDP runs synchronously in the packet path, so it only authorizes and
// binds the inner endpoint; dialing happens in serveUDP's goroutine.
func (s *session) handleUDP(r *udp.ForwarderRequest) bool {
	id := r.ID()
	f := Flow{
		Network: "udp",
		Src:     netstackutil.AddrPort(id.RemoteAddress, id.RemotePort),
		Dst:     netstackutil.AddrPort(id.LocalAddress, id.LocalPort),
	}
	if !s.admit(f) {
		return false
	}
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		// CreateEndpoint has already released the packet.
		s.log.Debug("tun udp endpoint failed", "dst", f.Dst, "err", terr)
		s.release()
		return true
	}
	go func() {
		defer s.release()
		s.serveUDP(f, gonet.NewUDPConn(&wq, ep))
	}()
	return true
}

// serveUDP relays datagrams for one association until neither direction has
// carried traffic for UDPIdleTimeout.
func (s *session) serveUDP(f Flow, in *gonet.UDPConn) {
	out, err := s.dial("udp", f.Dst)
	if err != nil {
		s.log.Debug("tun udp dial failed", "dst", f.Dst, "err", err)
		_ = in.Close()
		return
	}
	closeBoth := func() {
		_ = in.Close()
		_ = out.Close()
	}
	stop := context.AfterFunc(s.ctx, closeBoth)
	defer stop()
	defer closeBoth()

	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	idle := s.opts.UDPIdleTimeout

	relay := func(dst, src net.Conn) {
		defer closeBoth()
		buf := make([]byte, MaxPacketSize)
		for {
			_ = src.SetReadDeadline(time.Now().Add(idle))
			n, err := src.Read(buf)
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() &&
					time.Since(time.Unix(0, last.Load())) < idle {
					continue
				}
				return
			}
			last.Store(time.Now().UnixNano())
			if _, err := dst.Write(buf[:n]); err != nil {
				return
			}
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); relay(out, in) }()
	go func() { defer wg.Done(); relay(in, out) }()
	wg.Wait()
}
