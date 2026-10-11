//go:build linux

package client

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const tunClonePath = "/dev/net/tun"

// linuxTun is a TUN device read and written one packet at a time. It does not
// negotiate virtio offloads (GSO/GRO): that is faster but needs
// CAP_NET_ADMIN to set the MTU, which would break attaching to a persistent
// device as an unprivileged user.
type linuxTun struct {
	f    *os.File
	name string
	rbuf []byte
}

// openTunDevice creates the TUN device name, or attaches to an existing
// persistent one. An empty name lets the kernel pick tunN.
func openTunDevice(name string) (tunDevice, error) {
	fd, err := unix.Open(tunClonePath, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", tunClonePath, err)
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("tun device name %q: %w", name, err)
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		_ = unix.Close(fd)
		return nil, describeTunOpenError(name, err)
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return &linuxTun{
		f:    os.NewFile(uintptr(fd), tunClonePath),
		name: ifr.Name(),
		rbuf: make([]byte, 65536),
	}, nil
}

// describeTunOpenError explains a failed TUNSETIFF in terms of what to do.
func describeTunOpenError(name string, err error) error {
	switch {
	case errors.Is(err, unix.EBUSY):
		return fmt.Errorf("tun device %q is already attached by another process: %w (a persistent device can be used by one process at a time; stop the other one or use another device)", name, err)
	case errors.Is(err, unix.EPERM), errors.Is(err, unix.EACCES):
		return fmt.Errorf("cannot create or attach tun device %q: %w (creating a device needs CAP_NET_ADMIN; as an unprivileged user attach to a persistent one: ip tuntap add mode tun user $USER name NAME, then use tun://NAME?configure=false)", name, err)
	}
	return fmt.Errorf("create tun device %q: %w", name, err)
}

func (t *linuxTun) Name() string { return t.name }

// ReadPacket returns one IP packet; it is valid until the next call.
func (t *linuxTun) ReadPacket() ([]byte, error) {
	n, err := t.f.Read(t.rbuf)
	if err != nil {
		return nil, err
	}
	return t.rbuf[:n], nil
}

func (t *linuxTun) WritePacket(p []byte) error {
	_, err := t.f.Write(p)
	return err
}

// Close unblocks a pending ReadPacket and removes the device if it was not
// persistent.
func (t *linuxTun) Close() error { return t.f.Close() }

// deviceMTU reports the current MTU of ifname.
func deviceMTU(ifname string) (int, error) {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return 0, err
	}
	return iface.MTU, nil
}

func newNetConfigurer() netConfigurer { return netlinkConfigurer{} }

type netlinkConfigurer struct{}

func ipNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{
		IP:   net.IP(p.Addr().AsSlice()),
		Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen()),
	}
}

func (netlinkConfigurer) SetMTU(ifname string, mtu int) error {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}
	return netlink.LinkSetMTU(link, mtu)
}

func (netlinkConfigurer) AddAddr(ifname string, p netip.Prefix) error {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}
	return netlink.AddrAdd(link, &netlink.Addr{IPNet: ipNet(p)})
}

func (netlinkConfigurer) LinkUp(ifname string) error {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}
	return netlink.LinkSetUp(link)
}

func (netlinkConfigurer) AddRoute(ifname string, dst netip.Prefix) error {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return err
	}
	return netlink.RouteAdd(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       ipNet(dst),
		Scope:     netlink.SCOPE_LINK,
	})
}
