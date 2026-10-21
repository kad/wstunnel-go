package client

import (
	"errors"
	"io"
	"os"
	"reflect"
	"testing"

	"github.com/kad/wstunnel-go/pkg/protocol"
)

func TestParseTunnelArg(t *testing.T) {
	tests := []struct {
		name      string
		arg       string
		isReverse bool
		want      *protocol.LocalToRemote
		wantErr   bool
	}{
		{
			name: "Simple TCP",
			arg:  "tcp://8080:localhost:80",
			want: &protocol.LocalToRemote{
				Local:  "127.0.0.1:8080",
				Remote: "localhost",
				Port:   80,
				Protocol: protocol.LocalProtocol{
					Tcp: &protocol.TcpProtocol{ProxyProtocol: false},
				},
			},
		},
		{
			name: "TCP with proxy protocol",
			arg:  "tcp://8080:localhost:80?proxy_protocol",
			want: &protocol.LocalToRemote{
				Local:  "127.0.0.1:8080",
				Remote: "localhost",
				Port:   80,
				Protocol: protocol.LocalProtocol{
					Tcp: &protocol.TcpProtocol{ProxyProtocol: true},
				},
			},
		},
		{
			name: "UDP with timeout",
			arg:  "udp://1212:1.1.1.1:53?timeout_sec=10",
			want: &protocol.LocalToRemote{
				Local:  "127.0.0.1:1212",
				Remote: "1.1.1.1",
				Port:   53,
				Protocol: protocol.LocalProtocol{
					Udp: &protocol.UdpProtocol{Timeout: &protocol.Duration{Secs: 10}},
				},
			},
		},
		{
			name: "SOCKS5 with credentials",
			arg:  "socks5://[::1]:1212?login=admin&password=admin",
			want: &protocol.LocalToRemote{
				Local:  "[::1]:1212",
				Remote: "0.0.0.0",
				Port:   0,
				Protocol: protocol.LocalProtocol{
					Socks5: &protocol.Socks5Protocol{
						Timeout:     &protocol.Duration{Secs: 30},
						Credentials: &protocol.Credentials{Username: "admin", Password: "admin"},
					},
				},
			},
		},
		{
			name: "TCP with IPv6 remote",
			arg:  "tcp://8080:[::1]:80",
			want: &protocol.LocalToRemote{
				Local:  "127.0.0.1:8080",
				Remote: "::1",
				Port:   80,
				Protocol: protocol.LocalProtocol{
					Tcp: &protocol.TcpProtocol{ProxyProtocol: false},
				},
			},
		},
		{
			name: "Stdio",
			arg:  "stdio://google.com:443",
			want: &protocol.LocalToRemote{
				Local:  "",
				Remote: "google.com",
				Port:   443,
				Protocol: protocol.LocalProtocol{
					Stdio: &protocol.StdioProtocol{ProxyProtocol: false},
				},
			},
		},
		{
			name:      "Reverse TCP",
			arg:       "tcp://9090:localhost:443",
			isReverse: true,
			want: &protocol.LocalToRemote{
				Local:  "127.0.0.1:9090",
				Remote: "localhost",
				Port:   443,
				Protocol: protocol.LocalProtocol{
					ReverseTcp: &struct{}{},
				},
			},
		},
		{
			name:      "Reverse UDP",
			arg:       "udp://9090:localhost:53",
			isReverse: true,
			want: &protocol.LocalToRemote{
				Local:  "127.0.0.1:9090",
				Remote: "localhost",
				Port:   53,
				Protocol: protocol.LocalProtocol{
					ReverseUdp: &protocol.ReverseUdpProtocol{Timeout: &protocol.Duration{Secs: 30}},
				},
			},
		},
		{
			name:      "Reverse UDP with timeout",
			arg:       "udp://0.0.0.0:9090:10.0.0.1:53?timeout_sec=5",
			isReverse: true,
			want: &protocol.LocalToRemote{
				Local:  "0.0.0.0:9090",
				Remote: "10.0.0.1",
				Port:   53,
				Protocol: protocol.LocalProtocol{
					ReverseUdp: &protocol.ReverseUdpProtocol{Timeout: &protocol.Duration{Secs: 5}},
				},
			},
		},
		{
			name:      "Reverse SOCKS5",
			arg:       "socks5://9090",
			isReverse: true,
			want: &protocol.LocalToRemote{
				Local:  "127.0.0.1:9090",
				Remote: "0.0.0.0",
				Port:   0,
				Protocol: protocol.LocalProtocol{
					ReverseSocks5: &protocol.ReverseSocks5Protocol{Timeout: &protocol.Duration{Secs: 30}},
				},
			},
		},
		{
			name:      "Reverse HTTP proxy unsupported",
			arg:       "http://9090",
			isReverse: true,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseTunnelArg(tt.arg, tt.isReverse)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseTunnelArg() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseTunnelArg() got = %+v, want %v", got, tt.want)
			}
		})
	}
}

// timeout_sec follows Rust: absent or unreadable is 30 seconds, and 0 turns the
// timeout off, which is sent as no timeout.
func TestTimeoutOption(t *testing.T) {
	cases := []struct {
		arg  string
		want *protocol.Duration
	}{
		{"udp://9090:localhost:53", &protocol.Duration{Secs: 30}},
		{"udp://9090:localhost:53?timeout_sec=5", &protocol.Duration{Secs: 5}},
		{"udp://9090:localhost:53?timeout_sec=0", nil},
		{"udp://9090:localhost:53?timeout_sec=abc", &protocol.Duration{Secs: 30}},
		{"udp://9090:localhost:53?timeout_sec=", &protocol.Duration{Secs: 30}},
	}
	for _, tc := range cases {
		ltr, err := ParseTunnelArg(tc.arg, true)
		if err != nil {
			t.Fatalf("%s: %v", tc.arg, err)
		}
		got := ltr.Protocol.ReverseUdp.Timeout
		if (got == nil) != (tc.want == nil) || (got != nil && *got != *tc.want) {
			t.Errorf("%s: timeout = %+v, want %+v", tc.arg, got, tc.want)
		}
	}
}

func TestMarkReplyTimeoutOnlyAfterConnecting(t *testing.T) {
	if err := markReplyTimeout(os.ErrDeadlineExceeded, false); errors.Is(err, errReplyTimeout) {
		t.Error("a timeout while connecting was taken for a missing reply")
	}
	if err := markReplyTimeout(os.ErrDeadlineExceeded, true); !errors.Is(err, errReplyTimeout) || !isTimeout(err) {
		t.Errorf("a timeout after connecting was not marked: %v", err)
	}
	if err := markReplyTimeout(io.EOF, true); errors.Is(err, errReplyTimeout) {
		t.Error("a non-timeout error was marked as a missing reply")
	}
}
