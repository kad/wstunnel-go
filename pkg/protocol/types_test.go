package protocol

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestCredentials_JSON(t *testing.T) {
	c := Credentials{
		Username: "admin",
		Password: "password",
	}

	data, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	// Should be an array of two strings
	wantJSON := `["admin","password"]`
	if string(data) != wantJSON {
		t.Errorf("Marshal() got = %s, want %s", string(data), wantJSON)
	}

	var got Credentials
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if !reflect.DeepEqual(got, c) {
		t.Errorf("Unmarshal() got = %+v, want %+v", got, c)
	}
}

func TestCredentials_String(t *testing.T) {
	tests := []struct {
		name string
		cred Credentials
		want string
	}{
		{
			name: "with password",
			cred: Credentials{Username: "admin", Password: "secret123"},
			want: `Credentials{Username: "admin", Password: <redacted>}`,
		},
		{
			name: "empty password",
			cred: Credentials{Username: "admin", Password: ""},
			want: `Credentials{Username: "admin"}`,
		},
		{
			name: "empty username",
			cred: Credentials{Username: "", Password: "secret"},
			want: `Credentials{Username: "", Password: <redacted>}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cred.String()
			if got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}

			// Verify password is never in the output
			if tt.cred.Password != "" && strings.Contains(got, tt.cred.Password) {
				t.Errorf("String() contains password %q in output: %q", tt.cred.Password, got)
			}
		})
	}
}

func TestJwtTunnelConfig_JSON(t *testing.T) {
	cfg := JwtTunnelConfig{
		ID:     "test-id",
		Remote: "localhost",
		Port:   80,
		Protocol: LocalProtocol{
			Tcp: &TcpProtocol{ProxyProtocol: true},
		},
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	var got JwtTunnelConfig
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if got.ID != cfg.ID || got.Remote != cfg.Remote || got.Port != cfg.Port {
		t.Errorf("Unmarshal() basic fields mismatch: got %+v, want %+v", got, cfg)
	}

	if got.Protocol.Tcp == nil || got.Protocol.Tcp.ProxyProtocol != true {
		t.Errorf("Unmarshal() protocol mismatch: got %+v, want %+v", got.Protocol.Tcp, cfg.Protocol.Tcp)
	}
}
