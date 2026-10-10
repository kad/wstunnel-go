package client

import "github.com/kad/wstunnel-go/pkg/tun"

// tunDevice is a local TUN device: a source and sink of IP packets.
//
// It is the same shape as the transport side of a session (tun.PacketConn) plus
// the interface name, so tests can stand in an in-memory pipe for the kernel
// device and no root is needed to exercise the whole client loop.
type tunDevice interface {
	tun.PacketConn
	Name() string
}
