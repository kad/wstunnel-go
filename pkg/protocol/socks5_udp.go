package protocol

import (
	"encoding/binary"
	"errors"
	"net"
)

// ParseSocks5UDP reads the header of a datagram sent to a SOCKS5 UDP relay: reserved
// bytes, fragment number, and the destination address and port. It returns the
// destination and the length of the header. Fragmented datagrams are refused, as
// in Rust.
func ParseSocks5UDP(b []byte) (host string, port uint16, hdrLen int, err error) {
	if len(b) < 4 {
		return "", 0, 0, errors.New("short socks5 udp header")
	}
	if b[2] != 0 {
		return "", 0, 0, errors.New("fragmented socks5 udp datagram")
	}
	i := 4
	switch b[3] {
	case 0x01:
		if len(b) < i+4 {
			return "", 0, 0, errors.New("short socks5 udp header")
		}
		host = net.IP(b[i : i+4]).String()
		i += 4
	case 0x04:
		if len(b) < i+16 {
			return "", 0, 0, errors.New("short socks5 udp header")
		}
		host = net.IP(b[i : i+16]).String()
		i += 16
	case 0x03:
		if len(b) < i+1 || len(b) < i+1+int(b[i]) {
			return "", 0, 0, errors.New("short socks5 udp header")
		}
		n := int(b[i])
		host = string(b[i+1 : i+1+n])
		i += 1 + n
	default:
		return "", 0, 0, errors.New("unsupported socks5 udp address type")
	}
	if len(b) < i+2 {
		return "", 0, 0, errors.New("short socks5 udp header")
	}
	port = binary.BigEndian.Uint16(b[i : i+2])
	i += 2
	if host == "" || port == 0 {
		return "", 0, 0, errors.New("empty socks5 udp destination")
	}
	return host, port, i, nil
}

// Socks5UDPHeader builds the header that goes in front of datagrams coming back
// from the destination host:port.
func Socks5UDPHeader(host string, port uint16) []byte {
	h := []byte{0, 0, 0}
	switch ip := net.ParseIP(host); {
	case ip != nil && ip.To4() != nil:
		h = append(h, 0x01)
		h = append(h, ip.To4()...)
	case ip != nil:
		h = append(h, 0x04)
		h = append(h, ip.To16()...)
	default:
		h = append(h, 0x03, byte(len(host)))
		h = append(h, host...)
	}
	return binary.BigEndian.AppendUint16(h, port)
}
