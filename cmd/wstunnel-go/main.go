package main

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v3"

	"github.com/kad/wstunnel-go/internal/rlimit"
	"github.com/kad/wstunnel-go/pkg/client"
	"github.com/kad/wstunnel-go/pkg/server"
)

type FullConfig struct {
	Mode    string         `yaml:"mode"`
	LogLvl  string         `yaml:"log_lvl"`
	NoColor bool           `yaml:"no_color"`
	Client  *client.Config `yaml:"client"`
	Server  *server.Config `yaml:"server"`
}

func loadConfigFile(path string) (*FullConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &FullConfig{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func flagExplicitlySet(c *cli.Context, name string) bool {
	if c == nil {
		return false
	}
	return c.IsSet(name)
}

func applyClientFlagOverrides(c *cli.Context, config *client.Config, serverURL string, headers map[string]string) {
	if config == nil {
		return
	}
	if serverURL != "" {
		config.ServerURL = serverURL
	}
	if flagExplicitlySet(c, "http-upgrade-path-prefix") || config.PathPrefix == "" {
		config.PathPrefix = c.String("http-upgrade-path-prefix")
	}
	if flagExplicitlySet(c, "jwt-secret") || config.JWTSecret == "" {
		config.JWTSecret = c.String("jwt-secret")
	}
	if flagExplicitlySet(c, "header") || len(config.Headers) == 0 {
		config.Headers = headers
	}
	if flagExplicitlySet(c, "websocket-mask-frame") {
		config.MaskFrame = c.Bool("websocket-mask-frame")
	}
	if flagExplicitlySet(c, "websocket-ping-frequency") || config.PingFrequency == 0 {
		config.PingFrequency = c.Duration("websocket-ping-frequency")
	}
	if flagExplicitlySet(c, "tls-verify-certificate") {
		config.TlsVerifyCert = c.Bool("tls-verify-certificate")
	}
	if flagExplicitlySet(c, "tls-certificate") || config.TlsClientCert == "" {
		config.TlsClientCert = c.String("tls-certificate")
	}
	if flagExplicitlySet(c, "tls-private-key") || config.TlsClientKey == "" {
		config.TlsClientKey = c.String("tls-private-key")
	}
	if flagExplicitlySet(c, "tls-sni-override") || config.TlsSniOverride == "" {
		config.TlsSniOverride = c.String("tls-sni-override")
	}
	if flagExplicitlySet(c, "tls-sni-disable") {
		config.TlsSniDisable = c.Bool("tls-sni-disable")
	}
	if flagExplicitlySet(c, "tls-ech-enable") {
		config.TlsEchEnable = c.Bool("tls-ech-enable")
	}
	if flagExplicitlySet(c, "socket-so-mark") {
		config.SocketSoMark = uint32(c.Uint("socket-so-mark"))
	}
	if flagExplicitlySet(c, "connection-min-idle") {
		config.ConnectionMinIdle = uint32(c.Uint("connection-min-idle"))
	}
	if flagExplicitlySet(c, "connection-retry-max-backoff") || config.ConnectionRetryMaxBackoff == 0 {
		config.ConnectionRetryMaxBackoff = c.Duration("connection-retry-max-backoff")
	}
	if flagExplicitlySet(c, "reverse-tunnel-connection-retry-max-backoff") || config.ReverseTunnelConnectionRetryMaxBackoff == 0 {
		config.ReverseTunnelConnectionRetryMaxBackoff = c.Duration("reverse-tunnel-connection-retry-max-backoff")
	}
	if flagExplicitlySet(c, "http-proxy") || config.HttpProxy == "" {
		config.HttpProxy = c.String("http-proxy")
	}
	if flagExplicitlySet(c, "http-proxy-login") || config.HttpProxyLogin == "" {
		config.HttpProxyLogin = c.String("http-proxy-login")
	}
	if flagExplicitlySet(c, "http-proxy-password") || config.HttpProxyPassword == "" {
		config.HttpProxyPassword = c.String("http-proxy-password")
	}
	if flagExplicitlySet(c, "http-upgrade-credentials") || config.HttpUpgradeCredentials == "" {
		config.HttpUpgradeCredentials = c.String("http-upgrade-credentials")
	}
	if flagExplicitlySet(c, "http-headers-file") || config.HttpHeadersFile == "" {
		config.HttpHeadersFile = c.String("http-headers-file")
	}
	if flagExplicitlySet(c, "dns-resolver") || len(config.DnsResolver) == 0 {
		config.DnsResolver = c.StringSlice("dns-resolver")
	}
	if flagExplicitlySet(c, "dns-resolver-prefer-ipv4") {
		config.DnsResolverPreferIpv4 = c.Bool("dns-resolver-prefer-ipv4")
	}
	if flagExplicitlySet(c, "local-to-remote") || len(config.LocalToRemote) == 0 {
		config.LocalToRemote = c.StringSlice("local-to-remote")
	}
	if flagExplicitlySet(c, "remote-to-local") || len(config.RemoteToLocal) == 0 {
		config.RemoteToLocal = c.StringSlice("remote-to-local")
	}
	if flagExplicitlySet(c, "mode") || config.WebsocketProtocol == "" {
		config.WebsocketProtocol = c.String("mode")
	}
}

func applyServerFlagOverrides(c *cli.Context, config *server.Config, listenAddr string) {
	if config == nil {
		return
	}
	if listenAddr != "" {
		config.ListenAddr = listenAddr
	}
	if flagExplicitlySet(c, "http-upgrade-path-prefix") || config.PathPrefix == "" {
		config.PathPrefix = c.String("http-upgrade-path-prefix")
	}
	if flagExplicitlySet(c, "jwt-secret") || config.JWTSecret == "" {
		config.JWTSecret = c.String("jwt-secret")
	}
	if flagExplicitlySet(c, "insecure-no-jwt-validation") {
		config.InsecureNoJWTValidation = c.Bool("insecure-no-jwt-validation")
	}
	if flagExplicitlySet(c, "socket-so-mark") {
		config.SocketSoMark = uint32(c.Uint("socket-so-mark"))
	}
	if flagExplicitlySet(c, "websocket-ping-frequency") || config.WebsocketPingFrequency == 0 {
		config.WebsocketPingFrequency = c.Duration("websocket-ping-frequency")
	}
	if flagExplicitlySet(c, "websocket-mask-frame") {
		config.WebsocketMaskFrame = c.Bool("websocket-mask-frame")
	}
	if flagExplicitlySet(c, "dns-resolver") || len(config.DnsResolver) == 0 {
		config.DnsResolver = c.StringSlice("dns-resolver")
	}
	if flagExplicitlySet(c, "dns-resolver-prefer-ipv4") {
		config.DnsResolverPreferIpv4 = c.Bool("dns-resolver-prefer-ipv4")
	}
	if flagExplicitlySet(c, "restrict-to") || len(config.RestrictTo) == 0 {
		config.RestrictTo = c.StringSlice("restrict-to")
	}
	if flagExplicitlySet(c, "restrict-http-upgrade-path-prefix") || len(config.RestrictHttpUpgradePathPrefix) == 0 {
		config.RestrictHttpUpgradePathPrefix = c.StringSlice("restrict-http-upgrade-path-prefix")
	}
	if flagExplicitlySet(c, "restrict-config") || config.RestrictConfig == "" {
		config.RestrictConfig = c.String("restrict-config")
	}
	if flagExplicitlySet(c, "tls-certificate") || config.TlsCertificate == "" {
		config.TlsCertificate = c.String("tls-certificate")
	}
	if flagExplicitlySet(c, "tls-private-key") || config.TlsPrivateKey == "" {
		config.TlsPrivateKey = c.String("tls-private-key")
	}
	if flagExplicitlySet(c, "tls-client-ca-certs") || config.TlsClientCaCerts == "" {
		config.TlsClientCaCerts = c.String("tls-client-ca-certs")
	}
	if flagExplicitlySet(c, "http-proxy") || config.HttpProxy == "" {
		config.HttpProxy = c.String("http-proxy")
	}
	if flagExplicitlySet(c, "http-proxy-login") || config.HttpProxyLogin == "" {
		config.HttpProxyLogin = c.String("http-proxy-login")
	}
	if flagExplicitlySet(c, "http-proxy-password") || config.HttpProxyPassword == "" {
		config.HttpProxyPassword = c.String("http-proxy-password")
	}
	if flagExplicitlySet(c, "remote-to-local-server-idle-timeout") || config.RemoteToLocalServerIdleTimeout == 0 {
		config.RemoteToLocalServerIdleTimeout = c.Duration("remote-to-local-server-idle-timeout")
	}
	if flagExplicitlySet(c, "mode") || config.WebsocketProtocol == "" {
		config.WebsocketProtocol = c.String("mode")
	}
}

func main() {
	rlimit.RaiseFdLimit()
	app := &cli.App{
		Name:                   "wstunnel-go",
		Usage:                  "A Go client/server for wstunnel",
		UseShortOptionHandling: true,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "config",
				Usage:   "Path to config file (YAML)",
				EnvVars: []string{"WSTUNNEL_CONFIG"},
			},
			&cli.StringFlag{
				Name:    "no-color",
				Usage:   "Disable color output",
				EnvVars: []string{"NO_COLOR"},
			},
			&cli.IntFlag{
				Name:    "nb-worker-threads",
				Usage:   "Number of worker threads",
				EnvVars: []string{"TOKIO_WORKER_THREADS"},
			},
			&cli.StringFlag{
				Name:    "log-lvl",
				Value:   "INFO",
				Usage:   "Log verbosity (TRACE, DEBUG, INFO, WARN, ERROR, OFF)",
				EnvVars: []string{"WSTUNNEL_LOG_LVL", "RUST_LOG"},
			},
		},
		Before: func(c *cli.Context) error {
			setupLogging(c.String("log-lvl"))
			return nil
		},
		Commands: []*cli.Command{
			{
				Name:  "client",
				Usage: "Run wstunnel client",
				Flags: []cli.Flag{
					&cli.StringSliceFlag{
						Name:    "local-to-remote",
						Aliases: []string{"L"},
						Usage:   "Local to remote tunnel {tcp,udp,socks5,http,stdio,unix}://[BIND:]PORT:HOST:PORT",
					},
					&cli.StringSliceFlag{
						Name:    "remote-to-local",
						Aliases: []string{"R"},
						Usage:   "Remote to local tunnel {tcp,udp,socks5,http,unix}://[BIND:]PORT:HOST:PORT",
					},
					&cli.UintFlag{
						Name:  "socket-so-mark",
						Usage: "(linux only) Mark network packet with SO_MARK",
					},
					&cli.UintFlag{
						Name:    "connection-min-idle",
						Aliases: []string{"c"},
						Value:   0,
						Usage:   "Maximum number of idle connections in the pool",
					},
					&cli.DurationFlag{
						Name:    "connection-retry-max-backoff",
						Aliases: []string{"connection-retry-max-backoff-sec"},
						Value:   5 * time.Minute,
						Usage:   "Maximum retry backoff for server connection",
					},
					&cli.DurationFlag{
						Name:    "reverse-tunnel-connection-retry-max-backoff",
						Aliases: []string{"reverse-tunnel-connection-retry-max-backoff-sec"},
						Value:   1 * time.Second,
						Usage:   "Maximum retry backoff for reverse tunnels",
					},
					&cli.StringFlag{
						Name:  "tls-sni-override",
						Usage: "Domain name for SNI during TLS handshake",
					},
					&cli.BoolFlag{
						Name:  "tls-sni-disable",
						Usage: "Disable sending SNI during TLS handshake",
					},
					&cli.BoolFlag{
						Name:  "tls-ech-enable",
						Usage: "Enable ECH (encrypted sni) during TLS handshake",
					},
					&cli.BoolFlag{
						Name:  "tls-verify-certificate",
						Usage: "Enable TLS certificate verification",
					},
					&cli.StringFlag{
						Name:    "http-proxy",
						Aliases: []string{"p"},
						Usage:   "HTTP proxy to use for server connection",
						EnvVars: []string{"HTTP_PROXY"},
					},
					&cli.StringFlag{
						Name:    "http-proxy-login",
						Usage:   "Login for http proxy",
						EnvVars: []string{"WSTUNNEL_HTTP_PROXY_LOGIN"},
					},
					&cli.StringFlag{
						Name:    "http-proxy-password",
						Usage:   "Password for http proxy",
						EnvVars: []string{"WSTUNNEL_HTTP_PROXY_PASSWORD"},
					},
					&cli.StringFlag{
						Name:    "mode",
						Value:   "rust",
						Usage:   "WebSocket protocol mode (rust, ws)",
						EnvVars: []string{"WSTUNNEL_MODE"},
					},
					&cli.StringFlag{
						Name:  "jwt-secret",
						Usage: "Shared secret used to sign tunnel JWTs",
					},
					&cli.StringFlag{
						Name:    "http-upgrade-path-prefix",
						Aliases: []string{"prefix", "P"},
						Value:   "v1",
						Usage:   "HTTP upgrade path prefix",
						EnvVars: []string{"WSTUNNEL_HTTP_UPGRADE_PATH_PREFIX"},
					},
					&cli.StringFlag{
						Name:  "http-upgrade-credentials",
						Usage: "Basic auth credentials for upgrade request",
					},
					&cli.DurationFlag{
						Name:    "websocket-ping-frequency",
						Aliases: []string{"websocket-ping-frequency-sec"},
						Value:   30 * time.Second,
						Usage:   "Frequency of websocket pings",
					},
					&cli.BoolFlag{
						Name:  "websocket-mask-frame",
						Usage: "Enable masking of websocket frames",
					},
					&cli.StringSliceFlag{
						Name:    "header",
						Aliases: []string{"H", "http-headers"},
						Usage:   "Custom HTTP headers for upgrade request",
					},
					&cli.StringFlag{
						Name:  "http-headers-file",
						Usage: "File containing custom HTTP headers",
					},
					&cli.StringFlag{
						Name:  "tls-certificate",
						Usage: "Client certificate for mTLS",
					},
					&cli.StringFlag{
						Name:  "tls-private-key",
						Usage: "Private key for mTLS",
					},
					&cli.StringSliceFlag{
						Name:  "dns-resolver",
						Usage: "Dns resolver to use",
					},
					&cli.BoolFlag{
						Name:    "dns-resolver-prefer-ipv4",
						Usage:   "Prioritize IPv4 for DNS lookup",
						EnvVars: []string{"WSTUNNEL_DNS_PREFER_IPV4"},
					},
				},
				Action: runClient,
			},
			{
				Name:  "server",
				Usage: "Run wstunnel server",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "mode",
						Value:   "rust",
						Usage:   "WebSocket protocol mode (rust, ws)",
						EnvVars: []string{"WSTUNNEL_MODE"},
					},
					&cli.StringFlag{
						Name:  "jwt-secret",
						Usage: "Shared secret used to verify tunnel JWTs",
					},
					&cli.BoolFlag{
						Name:  "insecure-no-jwt-validation",
						Usage: "Allow unverified tunnel JWTs for compatibility",
					},
					&cli.StringFlag{
						Name:    "http-upgrade-path-prefix",
						Aliases: []string{"prefix", "P"},
						Value:   "v1",
						Usage:   "HTTP upgrade path prefix",
						EnvVars: []string{"WSTUNNEL_HTTP_UPGRADE_PATH_PREFIX"},
					},
					&cli.UintFlag{
						Name:  "socket-so-mark",
						Usage: "(linux only) Mark network packet with SO_MARK",
					},
					&cli.DurationFlag{
						Name:    "websocket-ping-frequency",
						Aliases: []string{"websocket-ping-frequency-sec"},
						Value:   30 * time.Second,
						Usage:   "Frequency of websocket pings",
					},
					&cli.BoolFlag{
						Name:  "websocket-mask-frame",
						Usage: "Enable masking of websocket frames",
					},
					&cli.StringSliceFlag{
						Name:  "dns-resolver",
						Usage: "Dns resolver to use",
					},
					&cli.BoolFlag{
						Name:    "dns-resolver-prefer-ipv4",
						Usage:   "Prioritize IPv4 for DNS lookup",
						EnvVars: []string{"WSTUNNEL_DNS_PREFER_IPV4"},
					},
					&cli.StringSliceFlag{
						Name:  "restrict-to",
						Usage: "Restrict tunnels to specific destinations",
					},
					&cli.StringSliceFlag{
						Name:    "restrict-http-upgrade-path-prefix",
						Aliases: []string{"r"},
						Usage:   "Restrict tunnels to specific path prefixes",
						EnvVars: []string{"WSTUNNEL_RESTRICT_HTTP_UPGRADE_PATH_PREFIX"},
					},
					&cli.StringFlag{
						Name:  "restrict-config",
						Usage: "Path to restriction config file",
					},
					&cli.StringFlag{
						Name:  "tls-certificate",
						Usage: "Custom TLS certificate path",
					},
					&cli.StringFlag{
						Name:  "tls-private-key",
						Usage: "Custom TLS private key path",
					},
					&cli.StringFlag{
						Name:  "tls-client-ca-certs",
						Usage: "Enables mTLS with specific CA certs",
					},
					&cli.StringFlag{
						Name:    "http-proxy",
						Aliases: []string{"p"},
						Usage:   "HTTP proxy to connect to client",
						EnvVars: []string{"HTTP_PROXY"},
					},
					&cli.StringFlag{
						Name:    "http-proxy-login",
						Usage:   "Login for http proxy",
						EnvVars: []string{"WSTUNNEL_HTTP_PROXY_LOGIN"},
					},
					&cli.StringFlag{
						Name:    "http-proxy-password",
						Usage:   "Password for http proxy",
						EnvVars: []string{"WSTUNNEL_HTTP_PROXY_PASSWORD"},
					},
					&cli.DurationFlag{
						Name:    "remote-to-local-server-idle-timeout",
						Aliases: []string{"remote-to-local-server-idle-timeout-sec"},
						Value:   3 * time.Minute,
						Usage:   "Idle timeout for reverse tunnel server",
					},
				},
				Action: runServer,
			},
		},
		Action: func(c *cli.Context) error {
			configPath := c.String("config")
			if configPath == "" {
				return cli.ShowAppHelp(c)
			}
			cfg, err := loadConfigFile(configPath)
			if err != nil {
				return err
			}
			if cfg.Mode == "client" && cfg.Client != nil {
				return startClient(c, cfg.Client)
			}
			if cfg.Mode == "server" && cfg.Server != nil {
				return startServer(c, cfg.Server)
			}
			return fmt.Errorf("invalid config file: mode and section mismatch")
		},
	}

	if err := app.Run(os.Args); err != nil {
		slog.Error("Application error", "err", err)
		os.Exit(1)
	}
}

func setupLogging(level string) {
	var slogLevel slog.Level
	switch strings.ToUpper(level) {
	case "TRACE", "DEBUG":
		slogLevel = slog.LevelDebug
	case "INFO":
		slogLevel = slog.LevelInfo
	case "WARN":
		slogLevel = slog.LevelWarn
	case "ERROR":
		slogLevel = slog.LevelError
	case "OFF":
		slogLevel = slog.LevelError + 100
	default:
		slogLevel = slog.LevelInfo
	}

	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slogLevel,
	})
	slog.SetDefault(slog.New(handler))
}

func runClient(c *cli.Context) error {
	var serverURL string
	if c.Args().Len() >= 1 {
		serverURL = c.Args().Get(c.Args().Len() - 1) // Get the last argument
	}

	headers := make(map[string]string)
	for _, h := range c.StringSlice("header") {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	config := &client.Config{}

	if c.String("config") != "" {
		cfg, _ := loadConfigFile(c.String("config"))
		if cfg != nil && cfg.Client != nil {
			*config = *cfg.Client
		}
	}
	applyClientFlagOverrides(c, config, serverURL, headers)

	if config.ServerURL == "" {
		return fmt.Errorf("server URL is required")
	}
	slog.Info("Starting client", "serverURL", config.ServerURL)

	return startClient(c, config)
}

func startClient(c *cli.Context, config *client.Config) error {
	wstClient := client.NewClient(*config)
	hasTunnels := false

	for _, arg := range config.LocalToRemote {
		ltr, err := client.ParseTunnelArg(arg, false)
		if err != nil {
			return fmt.Errorf("failed to parse local-to-remote tunnel %s: %w", arg, err)
		}
		go wstClient.StartTunnel(ltr)
		hasTunnels = true
	}

	for _, arg := range config.RemoteToLocal {
		rtr, err := client.ParseTunnelArg(arg, true)
		if err != nil {
			return fmt.Errorf("failed to parse remote-to-local tunnel %s: %w", arg, err)
		}
		go wstClient.StartReverseTunnel(rtr)
		hasTunnels = true
	}

	if !hasTunnels {
		return fmt.Errorf("no tunnels specified. Use -L or -R or config file")
	}

	select {}
}

func runServer(c *cli.Context) error {
	slog.Debug("runServer called", "args", c.Args().Slice())
	var listenAddr string
	if c.Args().Len() >= 1 {
		listenAddr = c.Args().Get(c.Args().Len() - 1) // Get the last argument
	}

	config := &server.Config{}

	if c.String("config") != "" {
		cfg, _ := loadConfigFile(c.String("config"))
		if cfg != nil && cfg.Server != nil {
			*config = *cfg.Server
		}
	}
	applyServerFlagOverrides(c, config, listenAddr)
	if config.ListenAddr == "" {
		config.ListenAddr = "ws://0.0.0.0:8080"
	}
	slog.Info("Starting server", "listenAddr", config.ListenAddr)

	return startServer(c, config)
}

func startServer(c *cli.Context, config *server.Config) error {
	srv := server.NewServer(*config)
	return srv.Start()
}
