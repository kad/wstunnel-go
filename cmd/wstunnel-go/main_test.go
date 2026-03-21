package main

import (
	"flag"
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
