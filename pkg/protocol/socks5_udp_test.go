package protocol

import (
	"net"
	"testing"
)

func TestParseSocks5UDP(t *testing.T) {
	cases := []struct {
		name    string
		in      []byte
		host    string
		port    uint16
		hdrLen  int
		wantErr bool
	}{
		{"ipv4", append([]byte{0, 0, 0, 1, 10, 0, 0, 7, 0x1F, 0x90}, "data"...), "10.0.0.7", 8080, 10, false},
		{"domain", append(append([]byte{0, 0, 0, 3, 11}, "example.org"...), 0x01, 0xBB, 'x'), "example.org", 443, 18, false},
		{"ipv6", append(append([]byte{0, 0, 0, 4}, net.ParseIP("2001:db8::1").To16()...), 0, 53), "2001:db8::1", 53, 22, false},
		{"fragmented", []byte{0, 0, 1, 1, 10, 0, 0, 7, 0, 80}, "", 0, 0, true},
		{"short", []byte{0, 0, 0, 1, 10}, "", 0, 0, true},
		{"port zero", []byte{0, 0, 0, 1, 10, 0, 0, 7, 0, 0}, "", 0, 0, true},
		{"unknown type", []byte{0, 0, 0, 9, 1, 2, 3, 4, 0, 80}, "", 0, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host, port, n, err := ParseSocks5UDP(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if err == nil && (host != tc.host || port != tc.port || n != tc.hdrLen) {
				t.Fatalf("got %s:%d hdr %d, want %s:%d hdr %d", host, port, n, tc.host, tc.port, tc.hdrLen)
			}
		})
	}
}

// The header built for replies parses back to the destination it was built for.
func TestSocks5UDPHeaderRoundTrip(t *testing.T) {
	for _, host := range []string{"10.0.0.7", "example.org", "2001:db8::1"} {
		h := Socks5UDPHeader(host, 5353)
		got, port, n, err := ParseSocks5UDP(append(h, "payload"...))
		if err != nil || got != host || port != 5353 || n != len(h) {
			t.Errorf("%s: parsed %s:%d header %d of %d, err %v", host, got, port, n, len(h), err)
		}
	}
}
