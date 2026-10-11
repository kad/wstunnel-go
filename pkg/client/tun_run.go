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
}

var defaultTunRetry = tunRetry{min: time.Second, max: 30 * time.Second, stable: 30 * time.Second}

// tunResolveTimeout bounds resolving the server name for the loop guard.
const tunResolveTimeout = 10 * time.Second

// StartTun creates and configures the TUN device described by spec, then
// carries its packets over a tun session to the server in the background,
// reconnecting when the session drops. It returns once the device is ready, or
// with the reason it could not be set up.
//
// The device and its routes outlive a dropped session, so traffic routed to
// the tunnel is dropped rather than leaking out of the default route while the
// client reconnects. Closing the process removes a device the client created.
func (c *Client) StartTun(spec *TunSpec) error {
	serverAddrs, err := c.resolveServerAddrs()
	if err != nil {
		return err
	}
	ops, err := planTunNetConfig(spec, serverAddrs)
	if err != nil {
		return err
	}

	dev, err := openTunDevice(spec.Name)
	if err != nil {
		return err
	}

	mtu := spec.MTU
	if spec.Configure {
		if err := applyNetOps(dev.Name(), ops, newNetConfigurer()); err != nil {
			_ = dev.Close()
			return err
		}
	} else {
		current, err := deviceMTU(dev.Name())
		if err != nil || current < tunMinMTU || current > tunMaxMTU {
			_ = dev.Close()
			return fmt.Errorf("tun device %s: usable MTU is %d..%d, device reports %d (err %v)", dev.Name(), tunMinMTU, tunMaxMTU, current, err)
		}
		mtu = uint16(current)
	}

	slog.Info("Tun device ready", "interface", dev.Name(), "mtu", mtu, "configured", spec.Configure)
	go func() {
		if err := c.runTun(context.Background(), dev, mtu, defaultTunRetry); err != nil {
			slog.Error("Tun device failed; tun tunnel stopped", "interface", dev.Name(), "err", err)
			os.Exit(1)
		}
	}()
	return nil
}

// lookupNetIP resolves a host name; a variable so tests can simulate a resolver
// that returns nothing.
var lookupNetIP = func(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// resolveServerAddrs returns the addresses the tunnel server name resolves to.
func (c *Client) resolveServerAddrs() ([]netip.Addr, error) {
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
	ctx, cancel := context.WithTimeout(context.Background(), tunResolveTimeout)
	defer cancel()
	addrs, err := lookupNetIP(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve tunnel server %q: %w", host, err)
	}
	if len(addrs) == 0 {
		// The loop guard must never run against an empty list.
		return nil, fmt.Errorf("resolve tunnel server %q: no addresses", host)
	}
	return addrs, nil
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
func (c *Client) runTun(ctx context.Context, dev tun.PacketConn, mtu uint16, retry tunRetry) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer func() { _ = dev.Close() }()

	var current atomic.Pointer[tunUplink]
	devErr := make(chan error, 1)
	go func() {
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

	delay := retry.min
	for ctx.Err() == nil {
		started := time.Now()
		err := c.tunSession(ctx, dev, mtu, &current)
		if ctx.Err() != nil {
			break
		}
		if time.Since(started) >= retry.stable {
			delay = retry.min
		}
		slog.Warn("Tun session ended; reconnecting", "err", err, "retry_in", delay)
		select {
		case <-ctx.Done():
		case <-time.After(delay):
		}
		delay = min(delay*2, retry.max)
	}

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
	ts := c.connectToTransport(protocol.LocalProtocol{Tun: &protocol.TunProtocol{Mtu: mtu}}, "0.0.0.0", 0)
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
	stop := context.AfterFunc(ctx, func() { _ = pc.Close() })
	defer stop()

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
		go c.tunKeepAlive(keepCtx, ts, pc, &lastAlive)
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
// HTTP/2 and WebTransport have no ping mechanism in this client, so they have
// no watchdog; their dead-peer detection is out of scope for this milestone.
func (c *Client) tunKeepAlive(ctx context.Context, ts *tunnelStream, pc tun.PacketConn, lastAlive *atomic.Int64) {
	if ts.ws == nil && ts.gorilla == nil {
		return
	}
	go func() {
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
	}()

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
