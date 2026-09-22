package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
)

// WriteJWTStreamPreamble writes the JWT as a length-prefixed preamble [u16 BE len][JWT bytes]
func WriteJWTStreamPreamble(w io.Writer, jwtStr string) error {
	jwtBytes := []byte(jwtStr)
	if len(jwtBytes) > 65535 {
		return fmt.Errorf("JWT preamble too long: %d bytes", len(jwtBytes))
	}
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(jwtBytes)))
	if err := writeFull(w, lenBuf[:]); err != nil {
		return fmt.Errorf("failed to write JWT preamble length: %w", err)
	}
	if err := writeFull(w, jwtBytes); err != nil {
		return fmt.Errorf("failed to write JWT preamble bytes: %w", err)
	}
	return nil
}

// ReadJWTStreamPreamble reads the length-prefixed JWT preamble [u16 BE len][JWT bytes]
func ReadJWTStreamPreamble(r io.Reader) (string, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return "", fmt.Errorf("failed to read JWT preamble length: %w", err)
	}
	l := binary.BigEndian.Uint16(lenBuf[:])
	if l == 0 || l > 8192 {
		return "", fmt.Errorf("invalid JWT preamble length: %d", l)
	}
	buf := make([]byte, l)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", fmt.Errorf("failed to read JWT preamble payload: %w", err)
	}
	return string(buf), nil
}

// FramedUDPReadWriteCloser wraps an io.ReadWriteCloser to add u16 big-endian length prefixing per UDP packet
type FramedUDPReadWriteCloser struct {
	io.ReadWriteCloser
	readBuf []byte
	pending []byte
}

func NewFramedUDPReadWriteCloser(rwc io.ReadWriteCloser) *FramedUDPReadWriteCloser {
	return &FramedUDPReadWriteCloser{
		ReadWriteCloser: rwc,
		readBuf:         make([]byte, 65536),
	}
}

func (f *FramedUDPReadWriteCloser) Write(p []byte) (int, error) {
	if len(p) > 65535 {
		return 0, fmt.Errorf("UDP packet too large: %d", len(p))
	}
	packet := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(packet[:2], uint16(len(p)))
	copy(packet[2:], p)
	if err := writeFull(f.ReadWriteCloser, packet); err != nil {
		return 0, err
	}
	return len(p), nil
}

func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

func (f *FramedUDPReadWriteCloser) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	if len(f.pending) > 0 {
		n := copy(p, f.pending)
		f.pending = f.pending[n:]
		return n, nil
	}

	packet, err := f.ReadPacket()
	if err != nil {
		return 0, err
	}
	f.pending = packet

	n := copy(p, f.pending)
	f.pending = f.pending[n:]
	return n, nil
}

// ReadPacket reads one complete framed UDP packet.
func (f *FramedUDPReadWriteCloser) ReadPacket() ([]byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(f.ReadWriteCloser, lenBuf[:]); err != nil {
		return nil, err
	}
	l := int(binary.BigEndian.Uint16(lenBuf[:]))
	if len(f.readBuf) < l {
		f.readBuf = make([]byte, l)
	}
	buf := f.readBuf[:l]
	if _, err := io.ReadFull(f.ReadWriteCloser, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
