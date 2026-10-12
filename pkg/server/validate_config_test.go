package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kad/wstunnel-go/pkg/protocol"
)

func writeFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestValidateConfig(t *testing.T) {
	good := writeFile(t, "restrictions:\n  - name: r\n    match: [Any]\n    allow:\n      - !Tunnel\n        protocol: [Tun]\n")
	bad := writeFile(t, "restrictions: [not, a, rule\n")
	missing := filepath.Join(t.TempDir(), "nope.yaml")
	for name, tc := range map[string]struct {
		cfg     Config
		wantErr string
	}{
		"empty config":         {Config{}, ""},
		"good rules file":      {Config{RestrictConfig: good}, ""},
		"missing rules file":   {Config{RestrictConfig: missing}, "restrict_config"},
		"malformed rules":      {Config{RestrictConfig: bad}, "restrict_config"},
		"bad tun_allow":        {Config{TunAllow: []string{"10.0.0.0/99"}}, "tun_allow"},
		"bad restrict-to":      {Config{RestrictTo: []string{"no-port"}}, "restrict_to"},
		"good restrict-to":     {Config{RestrictTo: []string{"10.0.0.1:22"}}, ""},
		"named port":           {Config{RestrictTo: []string{"10.0.0.1:http"}}, "restrict_to"},
		"port out of range":    {Config{RestrictTo: []string{"10.0.0.1:99999"}}, "restrict_to"},
		"port zero ok":         {Config{RestrictTo: []string{"10.0.0.1:0"}}, ""},
		"negative udp timeout": {Config{TunUdpTimeout: -time.Second}, "tun_udp_timeout"},
		"zero udp timeout":     {Config{}, ""},
		"both rules and flag":  {Config{RestrictConfig: missing, RestrictTo: []string{"10.0.0.1:22"}}, "restrict_config"},
	} {
		t.Run(name, func(t *testing.T) {
			err := ValidateConfig(tc.cfg)
			if tc.wantErr == "" && err != nil {
				t.Fatalf("ValidateConfig = %v, want nil", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("ValidateConfig = %v, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

// A server built in code from a restriction file that cannot be loaded must
// not fall back to "no restrictions": it refuses every tunnel.
func TestNewServerFailsClosedWhenRestrictConfigCannotBeLoaded(t *testing.T) {
	for name, cfg := range map[string]Config{
		"missing file":           {RestrictConfig: filepath.Join(t.TempDir(), "nope.yaml")},
		"missing file + flag":    {RestrictConfig: filepath.Join(t.TempDir(), "nope.yaml"), RestrictTo: []string{"10.0.0.1:22"}},
		"malformed file":         {RestrictConfig: writeFile(t, "restrictions: [oops\n")},
		"missing file, tun mode": {RestrictConfig: filepath.Join(t.TempDir(), "nope.yaml"), EnableTun: true},
	} {
		t.Run(name, func(t *testing.T) {
			s := NewServer(cfg)
			claims := &protocol.JwtTunnelConfig{
				ID:       "t",
				Protocol: protocol.LocalProtocol{Tcp: &protocol.TcpProtocol{}},
				Remote:   "10.0.0.1",
				Port:     22,
			}
			if _, ok := s.rules.ValidateMatch(claims, "/v1/events", "", ""); ok {
				t.Fatal("a tunnel was admitted although the restriction file did not load")
			}
			tun := &protocol.JwtTunnelConfig{ID: "t", Protocol: protocol.LocalProtocol{Tun: &protocol.TunProtocol{Mtu: 1500}}, Remote: "0.0.0.0"}
			if _, ok := s.rules.ValidateMatch(tun, "/v1/events", "", ""); ok {
				t.Fatal("a tun session was admitted although the restriction file did not load")
			}
		})
	}
}
