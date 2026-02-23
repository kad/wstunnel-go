package wst

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Message types
const (
	TextMessage   = 1
	BinaryMessage = 2
	CloseMessage  = 8
	PingMessage   = 9
	PongMessage   = 10
)

type Conn struct {
	rwc         net.Conn
	bufr        *bufio.Reader
	bufw        *bufio.Writer
	masking     bool
	muw         sync.Mutex
	mur         sync.Mutex
	pingHandler func(string) error
	pongHandler func(string) error
}

func NewConn(conn net.Conn, masking bool) *Conn {
	return NewConnWithReader(conn, masking, bufio.NewReader(conn))
}

func NewConnWithReader(conn net.Conn, masking bool, br *bufio.Reader) *Conn {
	c := &Conn{
		rwc:     conn,
		bufr:    br,
		bufw:    bufio.NewWriter(conn),
		masking: masking,
	}
	c.SetPingHandler(nil)
	c.SetPongHandler(nil)
	return c
}

func (c *Conn) Close() error {
	return c.rwc.Close()
}

func (c *Conn) SetPingHandler(h func(string) error) {
	if h == nil {
		h = func(message string) error {
			err := c.WriteControl(PongMessage, []byte(message), time.Now().Add(time.Second))
			if err == io.ErrClosedPipe || err == net.ErrClosed {
				return nil
			}
			return err
		}
	}
	c.pingHandler = h
}

func (c *Conn) SetPongHandler(h func(string) error) {
	if h == nil {
		h = func(string) error { return nil }
	}
	c.pongHandler = h
}

func (c *Conn) WriteControl(messageType int, data []byte, deadline time.Time) error {
	c.muw.Lock()
	defer c.muw.Unlock()

	b0 := byte(0x80) | byte(messageType)
	if err := c.bufw.WriteByte(b0); err != nil {
		return err
	}

	length := len(data)
	if length > 125 {
		return fmt.Errorf("control frame length %d > 125", length)
	}

	maskBit := byte(0)
	if c.masking {
		maskBit = 0x80
	}

	if err := c.bufw.WriteByte(maskBit | byte(length)); err != nil {
		return err
	}

	if c.masking {
		maskKey := []byte{0, 0, 0, 0}
		if _, err := c.bufw.Write(maskKey); err != nil {
			return err
		}
	}

	if _, err := c.bufw.Write(data); err != nil {
		return err
	}

	return c.bufw.Flush()
}

func (c *Conn) Subprotocol() string {
	return "v1" // Simplified
}

func (c *Conn) WriteMessage(messageType int, data []byte) error {
	c.muw.Lock()
	defer c.muw.Unlock()

	// Frame format:
	// 0: FIN(1) | RSV(0) | Opcode(4)
	// 1: MASK(1) | Len(7)
	// ExtLen (2 or 8 bytes)
	// MaskKey (0 or 4 bytes)
	// Payload

	b0 := byte(0x80) | byte(messageType) // FIN set
	if err := c.bufw.WriteByte(b0); err != nil {
		return err
	}

	length := len(data)
	maskBit := byte(0)
	if c.masking {
		maskBit = 0x80
	}

	if length <= 125 {
		if err := c.bufw.WriteByte(maskBit | byte(length)); err != nil {
			return err
		}
	} else if length <= 65535 {
		if err := c.bufw.WriteByte(maskBit | 126); err != nil {
			return err
		}
		if err := binary.Write(c.bufw, binary.BigEndian, uint16(length)); err != nil {
			return err
		}
	} else {
		if err := c.bufw.WriteByte(maskBit | 127); err != nil {
			return err
		}
		if err := binary.Write(c.bufw, binary.BigEndian, uint64(length)); err != nil {
			return err
		}
	}

	if c.masking {
		// Use a zero mask for simplicity/performance if "masking" is enabled but we want to be fast/interoperable.
		// However, to be strictly "unmasked" compatible, we might want masking=false.
		// If masking is true, we must write a mask key.
		// Let's use a dummy mask 0x00000000 for simplicity (effectively unmasked but compliant-ish header)
		maskKey := []byte{0, 0, 0, 0}
		if _, err := c.bufw.Write(maskKey); err != nil {
			return err
		}
		// With 0 mask, we write data as is
		if _, err := c.bufw.Write(data); err != nil {
			return err
		}
	} else {
		if _, err := c.bufw.Write(data); err != nil {
			return err
		}
	}

	return c.bufw.Flush()
}

func (c *Conn) ReadMessage() (int, []byte, error) {
	c.mur.Lock()
	defer c.mur.Unlock()

	for {
		// Read header
		b0, err := c.bufr.ReadByte()
		if err != nil {
			return 0, nil, err
		}

		// fin := b0 & 0x80
		opcode := int(b0 & 0x0F)

		b1, err := c.bufr.ReadByte()
		if err != nil {
			return 0, nil, err
		}

		mask := b1 & 0x80
		length := int64(b1 & 0x7F)

		switch length {
		case 126:
			var l uint16
			if err := binary.Read(c.bufr, binary.BigEndian, &l); err != nil {
				return 0, nil, err
			}
			length = int64(l)
		case 127:
			if err := binary.Read(c.bufr, binary.BigEndian, &length); err != nil {
				return 0, nil, err
			}
		}

		var maskKey []byte
		if mask != 0 {
			maskKey = make([]byte, 4)
			if _, err := io.ReadFull(c.bufr, maskKey); err != nil {
				return 0, nil, err
			}
		}

		// Read payload
		if length < 0 || length > 1024*1024*10 { // Max 10MB to prevent OOM
			return 0, nil, fmt.Errorf("payload length %d is out of bounds", length)
		}
		payload := make([]byte, int(length))
		if _, err := io.ReadFull(c.bufr, payload); err != nil {
			return 0, nil, err
		}

		if mask != 0 {
			// Unmask
			for i := range payload {
				payload[i] ^= maskKey[i%4]
			}
		}

		switch opcode {
		case PingMessage:
			if err := c.pingHandler(string(payload)); err != nil {
				return PingMessage, payload, err
			}
			continue
		case PongMessage:
			if err := c.pongHandler(string(payload)); err != nil {
				return PongMessage, payload, err
			}
			continue
		case CloseMessage:
			return CloseMessage, nil, io.EOF
		default:
			return opcode, payload, nil
		}
	}
}

// FormatCloseMessage matches gorilla/websocket signature
func FormatCloseMessage(closeCode int, text string) []byte {
	buf := make([]byte, 2+len(text))
	binary.BigEndian.PutUint16(buf, uint16(closeCode))
	copy(buf[2:], text)
	return buf
}

const CloseNormalClosure = 1000
