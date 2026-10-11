package client

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/kad/wstunnel-go/pkg/protocol"
	"github.com/kad/wstunnel-go/pkg/tun"
	"github.com/kad/wstunnel-go/pkg/wst"
)

// tunRetry controls how a dropped tun session is re-established.
type tunRetry struct {
	min    time.Duration // first delay
	max    time.Duration // delay ceiling
	stable time.Duration // a session this old resets the delay to min

	// sleep waits for d or until ctx ends; now reads the clock. Both are nil in
	// production and let tests observe the delays without waiting for them.
	sleep func(ctx context.Context, d time.Duration)
	now   func() time.Time
}

func (r tunRetry) wait(ctx context.Context, d time.Duration) {
	if r.sleep != nil {
		r.sleep(ctx, d)
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

func (r tunRetry) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

// backoff yields the delays between session attempts: min, doubling up to max,
// back to min after a session that lasted at least stable.
type backoff struct {
	retry tunRetry
	delay time.Duration
}

func newBackoff(r tunRetry) *backoff { return &backoff{retry: r, delay: r.min} }

func (b *backoff) next(sessionAge time.Duration) time.Duration {
	if sessionAge >= b.retry.stable {
		b.delay = b.retry.min
	}
	d := b.delay
	b.delay = min(b.delay*2, b.retry.max)
	return d
}

var defaultTunRetry = tunRetry{min: time.Second, max: 30 * time.Second, stable: 30 * time.Second}

// tunResolveTimeout bounds resolving the server name for the loop guard.
const tunResolveTimeout = 10 * time.Second

// TunHandle is a running tun tunnel: the device, the session loop and anything
// the client installed around them.
type TunHandle struct {
	name      string
	cancel    context.CancelFunc
	done      chan struct{}
	err       error // fatal reason; written before done is closed
	closeErr  error // cleanup failures; written before done is closed
	closeOnce sync.Once
}

// Name is the interface name of the TUN device.
func (h *TunHandle) Name() string { return h.name }

// Done is closed when the tunnel has stopped, whether because of Close, the
// context given to StartTun, or a fatal error.
func (h *TunHandle) Done() <-chan struct{} { return h.done }

// Err is nil until Done is closed. Afterwards it is the fatal reason the tunnel
// stopped, or nil for a clean stop (Close or a cancelled context).
func (h *TunHandle) Err() error {
	select {
	case <-h.done:
		return h.err
	default:
		return nil
	}
}

// Close stops the session loop, closes the device, removes everything the
// client installed and waits for all of it to finish. It is safe to call more
// than once and from several goroutines; every call returns the same result.
func (h *TunHandle) Close() error {
	h.closeOnce.Do(h.cancel)
	<-h.done
	return h.closeErr
}

// StartTun creates and configures the TUN device described by spec, then
// carries its packets over a tun session to the server in the background,
// reconnecting when the session drops. It returns once the device is ready, or
// with the reason it could not be set up.
//
// The device and its routes outlive a dropped session, so traffic routed to
// the tunnel is dropped rather than leaking out of the default route while the
// client reconnects. The tunnel runs until the returned handle is closed, ctx
// ends, or the device fails; the library never terminates the process.
func (c *Client) StartTun(ctx context.Context, spec *TunSpec) (*TunHandle, error) {
	return c.startTun(ctx, spec, defaultTunDeps(), defaultTunRetry)
}

func (c *Client) startTun(ctx context.Context, spec *TunSpec, deps tunDeps, retry tunRetry) (*TunHandle, error) {
	serverAddrs, err := c.resolveServerAddrs()
	if err != nil {
		return nil, err
	}
	ops, err := planTunNetConfig(spec, serverAddrs)
	if err != nil {
		return nil, err
	}
	var full *fullTunnel
	if spec.FullTunnel {
		if spec.Name != "" && deps.ifaceExists != nil && deps.ifaceExists(spec.Name) {
			return nil, fmt.Errorf("tun device %q already exists, and route=default needs a device this client creates itself, so that it disappears with the process: if the client crashed while a persistent device carried the default route, the host would have no usable route until someone removed it. Delete the device (`ip link del %s`) and let the client create it, or omit the name", spec.Name, spec.Name)
		}
		if full, err = c.prepareFullTunnel(spec, serverAddrs, deps); err != nil {
			return nil, err
		}
	}

	dev, err := deps.openDevice(spec.Name)
	if err != nil {
		return nil, err
	}

	mtu := spec.MTU
	var cleanups []func() error
	if spec.Configure {
		if err := applyNetOps(dev.Name(), ops, deps.nl); err != nil {
			_ = dev.Close()
			return nil, err
		}
		if full != nil {
			// DNS first: the link is up now, and resolvectl may be slow or hung
			// (it is bounded and never fatal); doing it before the routing
			// captures the host means the wait cannot happen while the host's
			// traffic is already routed into a tunnel that is not running yet.
			revertDNS := configureDNS(ctx, deps, dev.Name(), spec.DNS)
			cleanup, err := full.install(dev.Name(), deps.nl)
			if err != nil {
				_ = revertDNS()
				_ = dev.Close()
				return nil, err
			}
			// Cleanups run in reverse: the routing goes first, DNS last.
			cleanups = append(cleanups, revertDNS, cleanup)
		}
	} else {
		current, err := deps.deviceMTU(dev.Name())
		if err != nil || current < tunMinMTU || current > tunMaxMTU {
			_ = dev.Close()
			return nil, tunMTUError(dev.Name(), current, err)
		}
		mtu = uint16(current)
	}

	slog.Info("Tun device ready", "interface", dev.Name(), "mtu", mtu, "configured", spec.Configure)
	servers := c.newTunServers(spec, serverAddrs)
	servers.publish = full != nil
	preConnect := servers.guard
	if full != nil && full.pins != nil {
		preConnect = func(ctx context.Context) error {
			addrs, err := servers.refresh(ctx)
			if err != nil {
				return err
			}
			return full.pins.refresh(addrs)
		}
	}
	return c.startTunHandle(ctx, dev, dev.Name(), mtu, retry, preConnect, cleanups), nil
}

// startTunHandle runs the session loop for dev in the background. cleanups run
// in reverse order after the loop and the device are gone, whatever the reason
// it stopped.
func (c *Client) startTunHandle(ctx context.Context, dev tun.PacketConn, name string, mtu uint16, retry tunRetry, preConnect func(context.Context) error, cleanups []func() error) *TunHandle {
	ctx, cancel := context.WithCancel(ctx)
	h := &TunHandle{name: name, cancel: cancel, done: make(chan struct{})}
	go func() {
		err := c.runTun(ctx, dev, mtu, retry, preConnect)
		if err != nil {
			slog.Error("Tun device failed; tun tunnel stopped", "interface", name, "err", err)
		}
		var cleanupErrs []error
		for i := len(cleanups) - 1; i >= 0; i-- {
			if cerr := cleanups[i](); cerr != nil {
				cleanupErrs = append(cleanupErrs, cerr)
			}
		}
		cancel()
		h.err = err
		h.closeErr = errors.Join(cleanupErrs...)
		close(h.done)
	}()
	return h
}

// lookupNetIP resolves a host name; a variable so tests can simulate a resolver
// that returns nothing.
var lookupNetIP = func(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// tunMTUError explains why the MTU of an attached device cannot be used.
func tunMTUError(name string, current int, err error) error {
	if err != nil {
		return fmt.Errorf("tun device %s: cannot read its MTU: %w", name, err)
	}
	return fmt.Errorf("tun device %s: usable MTU is %d..%d, device reports %d", name, tunMinMTU, tunMaxMTU, current)
}

// resolveServerAddrs returns the addresses the tunnel server name resolves to.
func (c *Client) resolveServerAddrs() ([]netip.Addr, error) {
	return c.resolveServerAddrsCtx(context.Background())
}

func (c *Client) resolveServerAddrsCtx(ctx context.Context) ([]netip.Addr, error) {
	u, err := url.Parse(c.Config.ServerURL)
	if err != nil {
		return nil, fmt.Errorf("invalid server url: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("invalid server url %q: no hostname", c.Config.ServerURL)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, tunResolveTimeout)
	defer cancel()
	addrs, err := c.lookupHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve tunnel server %q: %w", host, err)
	}
	if len(addrs) == 0 {
		// The loop guard must never run against an empty list.
		return nil, fmt.Errorf("resolve tunnel server %q: no addresses", host)
	}
	return addrs, nil
}

// tunServers tracks the addresses of the tunnel server across reconnects.
type tunServers struct {
	c    *Client
	spec *TunSpec
	mu   sync.Mutex
	last []netip.Addr
	// publish makes the dial use the addresses that passed the guard (full
	// tunnel).
	publish bool
}

func (c *Client) newTunServers(spec *TunSpec, initial []netip.Addr) *tunServers {
	return &tunServers{c: c, spec: spec, last: slices.Clone(initial)}
}

// refresh is the loop guard: the server name is resolved again, because the
// answer can change while the client runs, and the loop checks are repeated
// against the new answer. When resolution fails or returns nothing the last
// addresses that passed the checks are used, so a reconnect works while DNS is
// unreachable; if there never were any, it fails closed. A refusal leaves those
// addresses unchanged.
func (s *tunServers) refresh(ctx context.Context) ([]netip.Addr, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	servers, err := s.c.resolveServerAddrsCtx(ctx)
	if err != nil {
		if len(s.last) == 0 {
			return nil, fmt.Errorf("tunnel server address never resolved: %w", err)
		}
		slog.Warn("Cannot re-resolve the tunnel server; using the last known addresses", "err", err, "addresses", s.last)
		servers = s.last
	}
	if err := checkTunLoops(s.spec, servers); err != nil {
		return nil, err
	}
	s.last = slices.Clone(servers)
	if s.publish {
		pinned := slices.Clone(servers)
		s.c.serverAddrs.Store(&pinned)
	}
	return slices.Clone(servers), nil
}

func (s *tunServers) guard(ctx context.Context) error {
	_, err := s.refresh(ctx)
	return err
}

// newTunGuard returns the loop guard to run before every session attempt.
func (c *Client) newTunGuard(spec *TunSpec, initial []netip.Addr) func(context.Context) error {
	return c.newTunServers(spec, initial).guard
}

// connectWithContext runs dial, which cannot be interrupted, in the background
// and returns as soon as it finishes or ctx ends. A stream that completes after
// ctx ended is closed, so cancelling never leaks a connection. The abandoned
// dial itself runs until the transport's own timeouts end it.
func connectWithContext(ctx context.Context, dial func() *tunnelStream) *tunnelStream {
	result := make(chan *tunnelStream, 1)
	go func() { result <- dial() }()
	select {
	case ts := <-result:
		return ts
	case <-ctx.Done():
		go func() {
			if ts := <-result; ts.err == nil {
				ts.Close()
			}
		}()
		return &tunnelStream{err: fmt.Errorf("connect aborted: %w", ctx.Err())}
	}
}

// tunUplink is the packet path of one established session.
type tunUplink struct {
	pc tun.PacketConn
}

// runTun moves packets between dev and the server until ctx ends or dev fails.
// It owns dev and closes it on return.
//
// A single goroutine reads dev for the whole run and hands packets to the
// current session, so a session can end and be replaced without having to
// interrupt a blocked device read. With no session the packets are dropped.
func (c *Client) runTun(ctx context.Context, dev tun.PacketConn, mtu uint16, retry tunRetry, preConnect func(context.Context) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var current atomic.Pointer[tunUplink]
	devErr := make(chan error, 1)
	var reader sync.WaitGroup
	reader.Add(1)
	go func() {
		defer reader.Done()
		for {
			pkt, err := dev.ReadPacket()
			if err != nil {
				if ctx.Err() == nil {
					devErr <- err
				}
				cancel()
				return
			}
			up := current.Load()
			if up == nil {
				continue
			}
			if err := up.pc.WritePacket(pkt); err != nil {
				// The session's reader notices the broken connection and ends.
				_ = up.pc.Close()
			}
		}
	}()

	backoff := newBackoff(retry)
	for ctx.Err() == nil {
		started := retry.clock()
		var err error
		if preConnect != nil {
			if perr := preConnect(ctx); perr != nil {
				err = fmt.Errorf("before connecting: %w", perr)
			}
		}
		if err == nil {
			err = c.tunSession(ctx, dev, mtu, &current)
		}
		if ctx.Err() != nil {
			break
		}
		delay := backoff.next(retry.clock().Sub(started))
		slog.Warn("Tun session ended; reconnecting", "err", err, "retry_in", delay)
		retry.wait(ctx, delay)
	}

	// Closing the device unblocks the reader; wait for it so nothing outlives
	// the call.
	cancel()
	_ = dev.Close()
	reader.Wait()
	select {
	case err := <-devErr:
		return err
	default:
		return nil
	}
}

// tunSession connects once and pumps server-to-device packets until the
// session ends. Device-to-server packets are sent by runTun's reader through
// current.
func (c *Client) tunSession(ctx context.Context, dev tun.PacketConn, mtu uint16, current *atomic.Pointer[tunUplink]) error {
	// Registered before the deferred ts.Close so that it runs after it: the
	// keepalive goroutines can be blocked in a write until the connection closes.
	var keepers sync.WaitGroup
	defer keepers.Wait()

	ts := connectWithContext(ctx, func() *tunnelStream {
		return c.connectToTransport(protocol.LocalProtocol{Tun: &protocol.TunProtocol{Mtu: mtu}}, "0.0.0.0", 0)
	})
	if ts.err != nil {
		return describeTunConnectError(ts)
	}
	defer ts.Close()

	pc, err := ts.tunPacketConn()
	if err != nil {
		return err
	}
	up := &tunUplink{pc: pc}
	current.Store(up)
	defer current.CompareAndSwap(up, nil)
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = pc.Close(); close(closed) })
	defer func() {
		// If the callback already started, wait for it so it cannot outlive the
		// session.
		if !stop() {
			<-closed
		}
	}()

	var lastAlive atomic.Int64
	lastAlive.Store(time.Now().UnixNano())
	if c.Config.PingFrequency > 0 {
		// The pong handler runs inside ReadMessage, hence the atomic.
		pong := func(string) error {
			lastAlive.Store(time.Now().UnixNano())
			return nil
		}
		switch {
		case ts.ws != nil:
			ts.ws.SetPongHandler(pong)
		case ts.gorilla != nil:
			ts.gorilla.SetPongHandler(pong)
		}
		keepCtx, keepCancel := context.WithCancel(ctx)
		defer keepCancel()
		keepers.Go(func() { c.tunKeepAlive(keepCtx, ts, pc, &lastAlive, &keepers) })
	}

	slog.Info("Tun session established", "mtu", mtu)
	for {
		pkt, err := pc.ReadPacket()
		if err != nil {
			return err
		}
		lastAlive.Store(time.Now().UnixNano())
		if err := dev.WritePacket(pkt); err != nil {
			if errors.Is(err, os.ErrClosed) {
				return err
			}
			// The kernel refuses malformed packets; one bad packet must not
			// take the session down.
			slog.Debug("Dropping packet the tun device refused", "err", err)
		}
	}
}

// tunKeepAlive sends websocket pings so idle NAT and proxy state stays alive,
// and drops the session when the peer has shown no sign of life (no packet and
// no pong) for three ping intervals, so a silently dead connection ends and
// runTun reconnects instead of hanging until the kernel's TCP timeout.
//
// The idle check and the ping write run independently: a ping write can block
// behind a packet write stuck on a full send buffer (the wst connection has no
// write deadline), and the check must still be able to close the session, which
// is what unblocks that write.
//
// HTTP/2 gets the same detection from the transport itself (see
// connectToHttp2). WebTransport has no client keepalive watchdog in this
// version.
func (c *Client) tunKeepAlive(ctx context.Context, ts *tunnelStream, pc tun.PacketConn, lastAlive *atomic.Int64, pinger *sync.WaitGroup) {
	if ts.ws == nil && ts.gorilla == nil {
		return
	}
	pinger.Go(func() {
		ticker := time.NewTicker(c.Config.PingFrequency)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			var err error
			if ts.ws != nil {
				err = ts.ws.WriteMessage(wst.PingMessage, nil)
			} else {
				// gorilla allows one writer; WriteControl is the call it documents
				// as safe alongside the packet writer.
				err = ts.gorilla.WriteControl(websocket.PingMessage, nil, time.Now().Add(time.Second))
			}
			if err != nil {
				_ = pc.Close()
				return
			}
		}
	})

	ticker := time.NewTicker(c.Config.PingFrequency)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		idle := time.Since(time.Unix(0, lastAlive.Load()))
		if idle > 3*c.Config.PingFrequency {
			slog.Warn("Tun peer unresponsive; dropping the session", "idle", idle)
			_ = pc.Close()
			return
		}
	}
}

// describeTunConnectError turns a failed connect into a message that tells the
// operator what to check.
func describeTunConnectError(ts *tunnelStream) error {
	if ts.r != nil && ts.r.StatusCode == http.StatusForbidden {
		return fmt.Errorf("%w (is the server started with --enable-tun, and does a restriction rule allow protocol Tun?)", ts.err)
	}
	return ts.err
}

// tunPacketConn adapts the established transport to whole-packet I/O.
func (ts *tunnelStream) tunPacketConn() (tun.PacketConn, error) {
	switch {
	case ts.ws != nil:
		return tun.NewWSTPacketConn(ts.ws), nil
	case ts.gorilla != nil:
		return tun.NewGorillaPacketConn(ts.gorilla), nil
	case ts.wt != nil:
		return tun.NewFramedPacketConn(ts.wt), nil
	case ts.h2 != nil:
		return tun.NewFramedPacketConn(ts.h2), nil
	}
	return nil, errors.New("no transport established")
}
