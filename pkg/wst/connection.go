package wst

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
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

// maxMessageSize is the default ceiling for one incoming message payload.
const maxMessageSize = 10 * 1024 * 1024

// ErrReadLimit is returned by ReadMessage when a frame announces a payload
// larger than the read limit. It mirrors gorilla's websocket.ErrReadLimit.
var ErrReadLimit = errors.New("wst: read limit exceeded")

type Conn struct {
	readLimit   atomic.Int64 // 0 means maxMessageSize
	rwc         net.Conn
	bufr        *bufio.Reader
	bufw        *bufio.Writer
	masking     bool
	muw         chan struct{} // write lock; a channel so WriteControl can give up waiting for it
	mur         sync.Mutex
	pingHandler func(string) error
	pongHandler func(string) error
	frameHook   atomic.Pointer[func()]
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
		muw:     make(chan struct{}, 1),
	}
	c.muw <- struct{}{}
	c.SetPingHandler(nil)
	c.SetPongHandler(nil)
	return c
}

// SetReadDeadline bounds the next ReadMessage calls; a zero time clears it.
func (c *Conn) SetReadDeadline(t time.Time) error { return c.rwc.SetReadDeadline(t) }

func (c *Conn) Close() error {
	return c.rwc.Close()
}

// SetReadLimit sets the largest message payload ReadMessage accepts; a frame
// announcing more fails with ErrReadLimit before any memory is allocated for
// it. Zero restores the default of 10 MiB, and the limit never exceeds it.
func (c *Conn) SetReadLimit(n int64) { c.readLimit.Store(n) }

func (c *Conn) maxPayload() int64 {
	if n := c.readLimit.Load(); n > 0 && n < maxMessageSize {
		return n
	}
	return maxMessageSize
}

func (c *Conn) SetPingHandler(h func(string) error) {
	if h == nil {
		h = func(message string) error {
			err := c.WriteControl(PongMessage, []byte(message), time.Now().Add(time.Second))
			if err == io.ErrClosedPipe || err == net.ErrClosed || errors.Is(err, ErrControlTimeout) {
				// A pong that cannot be written in time is dropped rather than
				// stalling the reader: the peer is not draining us, and a reader
				// stuck here would stop draining it in turn.
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

// SetFrameHook registers fn to be called for every frame ReadMessage receives,
// data and control alike, and again each time payload bytes of a large frame
// arrive. It is how a liveness watchdog learns the peer is alive
// even when a pong is stuck behind its bulk data. Pass nil to remove it.
func (c *Conn) SetFrameHook(fn func()) {
	if fn == nil {
		c.frameHook.Store(nil)
		return
	}
	c.frameHook.Store(&fn)
}

// ErrControlTimeout is returned by WriteControl when the frame could not be
// written before its deadline. The connection stays usable: either nothing of
// the frame was sent, or it is still being sent whole by a goroutine that holds
// the write lock until the peer drains.
var ErrControlTimeout = errors.New("wst: control frame write timeout")

// WriteControl sends a control frame, giving up with ErrControlTimeout when the
// write lock (held by a WriteMessage stuck on a full send buffer) or the socket
// does not free up before deadline. A zero deadline waits indefinitely. It
// never sets a deadline on the socket, so it is safe on a tls.Conn.
func (c *Conn) WriteControl(messageType int, data []byte, deadline time.Time) error {
	if len(data) > 125 {
		return fmt.Errorf("control frame length %d > 125", len(data))
	}

	var expired <-chan time.Time
	if !deadline.IsZero() {
		d := time.Until(deadline)
		if d <= 0 {
			return ErrControlTimeout
		}
		t := time.NewTimer(d)
		defer t.Stop()
		expired = t.C
	}
	select {
	case <-c.muw:
	case <-expired:
		return ErrControlTimeout
	}

	frame := make([]byte, 0, 2+4+len(data))
	frame = append(frame, byte(0x80)|byte(messageType))
	if c.masking {
		// Zero mask key, like WriteMessage: a compliant header with unmasked data.
		frame = append(frame, 0x80|byte(len(data)), 0, 0, 0, 0)
	} else {
		frame = append(frame, byte(len(data)))
	}
	frame = append(frame, data...)

	// The previous WriteMessage flushed completely, so the frame goes straight
	// to the socket. No write deadline is set on it: on a tls.Conn a write
	// timeout is permanent, so every later write would fail even though no
	// byte was sent. Instead the write runs on its own goroutine, which keeps
	// the write lock until it finishes. Giving up at the deadline returns
	// ErrControlTimeout, the frame still goes out whole once the peer drains,
	// and meanwhile other control writes time out on the lock without
	// spawning anything.
	write := func() error {
		n, err := c.rwc.Write(frame)
		if err != nil && n > 0 && n < len(frame) {
			// Half a frame is on the wire; the stream cannot be resynchronised.
			_ = c.rwc.Close()
		}
		return err
	}
	if deadline.IsZero() {
		defer func() { c.muw <- struct{}{} }()
		return write()
	}
	res := make(chan error, 1)
	go func() {
		err := write()
		c.muw <- struct{}{}
		res <- err
	}()
	select {
	case err := <-res:
		return err
	case <-expired:
		return ErrControlTimeout
	}
}

func (c *Conn) Subprotocol() string {
	return "v1" // Simplified
}

func (c *Conn) WriteMessage(messageType int, data []byte) error {
	<-c.muw
	defer func() { c.muw <- struct{}{} }()

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
		if h := c.frameHook.Load(); h != nil {
			(*h)()
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
		if length < 0 {
			return 0, nil, fmt.Errorf("payload length %d is out of bounds", length)
		}
		if limit := c.maxPayload(); length > limit {
			return 0, nil, fmt.Errorf("%w: payload length %d, limit %d", ErrReadLimit, length, limit)
		}
		payload := make([]byte, int(length))
		// Report progress as bytes arrive, not once per full read, so a large
		// frame trickling in over a slow link keeps a liveness watchdog
		// satisfied until it is complete.
		for off := 0; off < len(payload); {
			n, err := c.bufr.Read(payload[off:])
			if n > 0 {
				off += n
				if h := c.frameHook.Load(); h != nil {
					(*h)()
				}
			}
			if err != nil && off < len(payload) {
				if err == io.EOF {
					err = io.ErrUnexpectedEOF
				}
				return 0, nil, err
			}
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
