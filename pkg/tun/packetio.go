// Package tun carries whole IP packets over an established wstunnel
// connection and, on the server side, terminates them in a userspace TCP/IP
// stack that forwards each flow to the real network.
package tun

import (
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/kad/wstunnel-go/pkg/protocol"
	"github.com/kad/wstunnel-go/pkg/wst"
)

// MaxPacketSize is the largest IP packet a PacketConn carries. It matches the
// u16 length prefix used by the stream framing.
const MaxPacketSize = 65535

// ErrPacketTooLarge is returned for packets larger than MaxPacketSize.
var ErrPacketTooLarge = errors.New("tun: packet larger than 65535 bytes")

// PacketConn moves whole IP packets over a tunnel transport.
//
// The slice returned by ReadPacket is only valid until the next ReadPacket
// call. WritePacket must not retain p. ReadPacket and WritePacket may be called
// concurrently with each other, but each must only be called from one goroutine
// at a time.
type PacketConn interface {
	ReadPacket() ([]byte, error)
	WritePacket(p []byte) error
	Close() error
}

type wstPacketConn struct {
	c *wst.Conn
}

// NewWSTPacketConn carries one IP packet per binary message on a custom
// (--mode rust) WebSocket connection.
func NewWSTPacketConn(c *wst.Conn) PacketConn {
	return &wstPacketConn{c: c}
}

func (p *wstPacketConn) ReadPacket() ([]byte, error) {
	for {
		mt, data, err := p.c.ReadMessage()
		if err != nil {
			return nil, err
		}
		if mt != wst.BinaryMessage {
			continue
		}
		if len(data) > MaxPacketSize {
			return nil, ErrPacketTooLarge
		}
		return data, nil
	}
}

func (p *wstPacketConn) WritePacket(b []byte) error {
	if len(b) > MaxPacketSize {
		return ErrPacketTooLarge
	}
	return p.c.WriteMessage(wst.BinaryMessage, b)
}

func (p *wstPacketConn) Close() error { return p.c.Close() }

type gorillaPacketConn struct {
	c  *websocket.Conn
	mu sync.Mutex
}

// NewGorillaPacketConn carries one IP packet per binary message on an RFC 6455
// (--mode ws) connection.
//
// gorilla allows only one concurrent writer, so this replaces the connection's
// ping handler with one that answers through WriteControl, which gorilla
// documents as safe to call alongside WriteMessage.
func NewGorillaPacketConn(c *websocket.Conn) PacketConn {
	c.SetPingHandler(func(appData string) error {
		err := c.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(time.Second))
		if errors.Is(err, websocket.ErrCloseSent) {
			return nil
		}
		return err
	})
	return &gorillaPacketConn{c: c}
}

func (p *gorillaPacketConn) ReadPacket() ([]byte, error) {
	for {
		mt, data, err := p.c.ReadMessage()
		if err != nil {
			return nil, err
		}
		if mt != websocket.BinaryMessage {
			continue
		}
		if len(data) > MaxPacketSize {
			return nil, ErrPacketTooLarge
		}
		return data, nil
	}
}

func (p *gorillaPacketConn) WritePacket(b []byte) error {
	if len(b) > MaxPacketSize {
		return ErrPacketTooLarge
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.c.WriteMessage(websocket.BinaryMessage, b)
}

func (p *gorillaPacketConn) Close() error { return p.c.Close() }

type framedPacketConn struct {
	f *protocol.FramedUDPReadWriteCloser
}

// NewFramedPacketConn carries IP packets over a byte stream (HTTP/2 body,
// WebTransport stream) using a u16 big-endian length prefix per packet.
func NewFramedPacketConn(rwc io.ReadWriteCloser) PacketConn {
	return &framedPacketConn{f: protocol.NewFramedUDPReadWriteCloser(rwc)}
}

func (p *framedPacketConn) ReadPacket() ([]byte, error) {
	return p.f.ReadPacket()
}

func (p *framedPacketConn) WritePacket(b []byte) error {
	if len(b) > MaxPacketSize {
		return ErrPacketTooLarge
	}
	if _, err := p.f.Write(b); err != nil {
		return fmt.Errorf("tun: write framed packet: %w", err)
	}
	return nil
}

func (p *framedPacketConn) Close() error { return p.f.Close() }
