package main

import (
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/kad/wstunnel-go/pkg/client"
	"github.com/kad/wstunnel-go/pkg/server"
	"github.com/urfave/cli/v2"
)

func newTestContext(t *testing.T, args []string) *cli.Context {
	t.Helper()

	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("http-upgrade-path-prefix", "v1", "")
	fs.String("jwt-secret", "", "")
	fs.Bool("websocket-mask-frame", false, "")
	fs.Duration("websocket-ping-frequency", 30*time.Second, "")
	fs.Bool("tls-verify-certificate", false, "")
	fs.String("tls-certificate", "", "")
	fs.String("tls-private-key", "", "")
	fs.String("tls-sni-override", "", "")
	fs.Bool("tls-sni-disable", false, "")
	fs.Bool("tls-ech-enable", false, "")
	fs.Uint("socket-so-mark", 0, "")
	fs.Uint("connection-min-idle", 0, "")
	fs.Duration("connection-retry-max-backoff", 5*time.Minute, "")
	fs.Duration("reverse-tunnel-connection-retry-max-backoff", time.Second, "")
	fs.String("http-proxy", "", "")
	fs.String("http-proxy-login", "", "")
	fs.String("http-proxy-password", "", "")
	fs.String("http-upgrade-credentials", "", "")
	fs.String("http-headers-file", "", "")
	fs.Var(cli.NewStringSlice(), "header", "")
	fs.Var(cli.NewStringSlice(), "dns-resolver", "")
	fs.Bool("dns-resolver-prefer-ipv4", false, "")
	fs.Var(cli.NewStringSlice(), "local-to-remote", "")
	fs.Var(cli.NewStringSlice(), "remote-to-local", "")
	fs.String("mode", "rust", "")
	fs.Bool("insecure-no-jwt-validation", false, "")
	fs.Var(cli.NewStringSlice(), "restrict-to", "")
	fs.Var(cli.NewStringSlice(), "restrict-http-upgrade-path-prefix", "")
	fs.String("restrict-config", "", "")
	fs.String("tls-client-ca-certs", "", "")
	fs.Duration("remote-to-local-server-idle-timeout", 0, "")
	fs.Var(cli.NewStringSlice(), "tun-allow", "")
	fs.Bool("enable-tun", false, "")
	fs.Duration("tun-udp-timeout", 30*time.Second, "")
	fs.Int("tun-max-flows", 4096, "")
	fs.Int("tun-max-sessions", 256, "")

	if err := fs.Parse(args); err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	return cli.NewContext(&cli.App{}, fs, nil)
}

func TestApplyClientFlagOverridesKeepsConfigValuesOverDefaults(t *testing.T) {
	cfg := &client.Config{
		ServerURL:         "ws://example.com",
		PathPrefix:        "cfg-prefix",
		JWTSecret:         "cfg-secret",
		WebsocketProtocol: "ws",
		PingFrequency:     time.Minute,
	}

	applyClientFlagOverrides(newTestContext(t, nil), cfg, "", nil)

	if cfg.PathPrefix != "cfg-prefix" {
		t.Fatalf("PathPrefix = %q, want cfg-prefix", cfg.PathPrefix)
	}
	if cfg.JWTSecret != "cfg-secret" {
		t.Fatalf("JWTSecret = %q, want cfg-secret", cfg.JWTSecret)
	}
	if cfg.WebsocketProtocol != "ws" {
		t.Fatalf("WebsocketProtocol = %q, want ws", cfg.WebsocketProtocol)
	}
	if cfg.PingFrequency != time.Minute {
		t.Fatalf("PingFrequency = %v, want %v", cfg.PingFrequency, time.Minute)
	}
}

func TestApplyServerFlagOverridesRespectsExplicitBoolOverride(t *testing.T) {
	cfg := &server.Config{
		ListenAddr:              "ws://127.0.0.1:8080",
		PathPrefix:              "cfg-prefix",
		JWTSecret:               "cfg-secret",
		InsecureNoJWTValidation: true,
		WebsocketProtocol:       "ws",
		WebsocketPingFrequency:  time.Minute,
	}

	applyServerFlagOverrides(newTestContext(t, []string{"--mode=rust", "--insecure-no-jwt-validation=false"}), cfg, "")

	if cfg.PathPrefix != "cfg-prefix" {
		t.Fatalf("PathPrefix = %q, want cfg-prefix", cfg.PathPrefix)
	}
	if cfg.JWTSecret != "cfg-secret" {
		t.Fatalf("JWTSecret = %q, want cfg-secret", cfg.JWTSecret)
	}
	if cfg.InsecureNoJWTValidation {
		t.Fatal("InsecureNoJWTValidation remained true despite explicit false override")
	}
	if cfg.WebsocketProtocol != "rust" {
		t.Fatalf("WebsocketProtocol = %q, want rust", cfg.WebsocketProtocol)
	}
	if cfg.WebsocketPingFrequency != time.Minute {
		t.Fatalf("WebsocketPingFrequency = %v, want %v", cfg.WebsocketPingFrequency, time.Minute)
	}
}

func TestApplyServerFlagOverridesTunSettings(t *testing.T) {
	cfg := &server.Config{TunUdpTimeout: time.Minute}
	applyServerFlagOverrides(newTestContext(t, []string{"--enable-tun"}), cfg, "")
	if !cfg.EnableTun {
		t.Fatal("EnableTun = false, want true from --enable-tun")
	}
	if cfg.TunUdpTimeout != time.Minute {
		t.Fatalf("TunUdpTimeout = %v, want config value %v over the flag default", cfg.TunUdpTimeout, time.Minute)
	}

	cfg = &server.Config{EnableTun: true}
	applyServerFlagOverrides(newTestContext(t, []string{"--enable-tun=false", "--tun-udp-timeout=5s"}), cfg, "")
	if cfg.EnableTun {
		t.Fatal("EnableTun remained true despite explicit --enable-tun=false")
	}
	if cfg.TunUdpTimeout != 5*time.Second {
		t.Fatalf("TunUdpTimeout = %v, want 5s", cfg.TunUdpTimeout)
	}

	cfg = &server.Config{}
	applyServerFlagOverrides(newTestContext(t, nil), cfg, "")
	if cfg.EnableTun || cfg.TunUdpTimeout != 30*time.Second {
		t.Fatalf("defaults = EnableTun %v, TunUdpTimeout %v; want false, 30s", cfg.EnableTun, cfg.TunUdpTimeout)
	}
}

func TestApplyServerFlagOverridesTunLimits(t *testing.T) {
	cfg := &server.Config{TunMaxFlows: 10}
	applyServerFlagOverrides(newTestContext(t, nil), cfg, "")
	if cfg.TunMaxFlows != 10 || cfg.TunMaxSessions != 256 {
		t.Fatalf("limits = %d/%d, want config 10 and default 256", cfg.TunMaxFlows, cfg.TunMaxSessions)
	}

	cfg = &server.Config{TunMaxFlows: 10, TunMaxSessions: 3}
	applyServerFlagOverrides(newTestContext(t, []string{"--tun-max-flows=7", "--tun-max-sessions=2"}), cfg, "")
	if cfg.TunMaxFlows != 7 || cfg.TunMaxSessions != 2 {
		t.Fatalf("limits = %d/%d, want explicit flags 7/2", cfg.TunMaxFlows, cfg.TunMaxSessions)
	}

	cfg = &server.Config{}
	applyServerFlagOverrides(newTestContext(t, nil), cfg, "")
	if cfg.TunMaxFlows != 4096 || cfg.TunMaxSessions != 256 {
		t.Fatalf("defaults = %d/%d, want 4096/256", cfg.TunMaxFlows, cfg.TunMaxSessions)
	}
}

func TestLoadConfigFileCarriesTunTunnel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.yaml")
	const arg = "tun://wst0?addr=198.18.0.1/32&route=10.0.0.0/8&route=172.16.0.0/12&mtu=1400"
	if err := os.WriteFile(path, []byte("mode: client\nclient:\n  remote_addr: wss://tunnel.example.com\n  local_to_remote:\n    - \""+arg+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Client == nil || len(cfg.Client.LocalToRemote) != 1 || cfg.Client.LocalToRemote[0] != arg {
		t.Fatalf("LocalToRemote = %+v, want the tun:// argument unchanged", cfg.Client)
	}
	spec, err := client.ParseTunArg(cfg.Client.LocalToRemote[0])
	if err != nil || spec.MTU != 1400 || len(spec.Routes) != 2 {
		t.Fatalf("ParseTunArg = %+v, %v", spec, err)
	}
}

func TestApplyServerFlagOverridesTunAllow(t *testing.T) {
	cfg := &server.Config{TunAllow: []string{"10.0.0.0/8"}}
	applyServerFlagOverrides(newTestContext(t, nil), cfg, "")
	if len(cfg.TunAllow) != 1 || cfg.TunAllow[0] != "10.0.0.0/8" {
		t.Fatalf("TunAllow = %v, want the config value kept when the flag is not set", cfg.TunAllow)
	}

	cfg = &server.Config{TunAllow: []string{"10.0.0.0/8"}}
	applyServerFlagOverrides(newTestContext(t, []string{"--tun-allow=192.0.2.0/24", "--tun-allow=203.0.113.9"}), cfg, "")
	if len(cfg.TunAllow) != 2 || cfg.TunAllow[0] != "192.0.2.0/24" || cfg.TunAllow[1] != "203.0.113.9" {
		t.Fatalf("TunAllow = %v, want the explicit flag values to replace the config", cfg.TunAllow)
	}
}

func TestRunRejectsUnreadableConfigFile(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(bad, []byte("server: [not, a, mapping\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{bad, filepath.Join(t.TempDir(), "missing.yaml")} {
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		fs.String("config", path, "")
		ctx := cli.NewContext(&cli.App{}, fs, nil)
		for name, run := range map[string]func(*cli.Context) error{"server": runServer, "client": runClient} {
			err := run(ctx)
			if err == nil || !strings.Contains(err.Error(), "loading config file") {
				t.Errorf("%s with %s: got %v, want a config load error", name, path, err)
			}
		}
	}
}

func TestStartServerRefusesAnUnloadableRestrictConfig(t *testing.T) {
	cfg := &server.Config{
		ListenAddr:     "ws://127.0.0.1:0",
		EnableTun:      true,
		RestrictConfig: filepath.Join(t.TempDir(), "missing.yaml"),
	}
	err := startServer(nil, cfg)
	if err == nil || !strings.Contains(err.Error(), "restrict_config") {
		t.Fatalf("startServer = %v, want a restrict_config error before anything is served", err)
	}
}

func TestApplyWorkerThreads(t *testing.T) {
	prev := runtime.GOMAXPROCS(0)
	t.Cleanup(func() { runtime.GOMAXPROCS(prev) })

	if err := applyWorkerThreads(0); err != nil || runtime.GOMAXPROCS(0) != prev {
		t.Fatalf("0 must keep the default: err=%v procs=%d want %d", err, runtime.GOMAXPROCS(0), prev)
	}
	if err := applyWorkerThreads(1); err != nil || runtime.GOMAXPROCS(0) != 1 {
		t.Fatalf("1: err=%v procs=%d, want 1", err, runtime.GOMAXPROCS(0))
	}
	if err := applyWorkerThreads(-1); err == nil {
		t.Fatal("negative value accepted")
	}
}
