package caddy

import (
	"bufio"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/kad/wstunnel-go/pkg/server"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Wstunnel{})
	// Without these the "wstunnel" block shown in the README is rejected with
	// "not a registered directive". Running before reverse_proxy lets a site
	// proxy everything else while wstunnel answers its own path.
	httpcaddyfile.RegisterHandlerDirective("wstunnel", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("wstunnel", httpcaddyfile.Before, "reverse_proxy")
}

// parseCaddyfile builds the handler from the "wstunnel" directive.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var w Wstunnel
	if err := w.UnmarshalCaddyfile(h.Dispenser); err != nil {
		return nil, err
	}
	return &w, nil
}

// Wstunnel is a Caddy module that allows serving wstunnels.
type Wstunnel struct {
	// The configuration for the wstunnel server.
	Config server.Config `json:"config,omitempty"`

	// Inline restrictions.
	Restrictions []server.RestrictionConfig `json:"restrictions,omitempty"`

	server *server.Server
	log    *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Wstunnel) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.wstunnel",
		New: func() caddy.Module { return new(Wstunnel) },
	}
}

// Provision sets up the module.
func (w *Wstunnel) Provision(ctx caddy.Context) error {
	w.log = ctx.Logger()
	// The server logs through slog's default logger; send that to Caddy's log
	// so levels, format and outputs follow the Caddy configuration.
	slog.SetDefault(ctx.Slogger())

	// If no mode is specified, default to rust for compatibility
	if w.Config.WebsocketProtocol == "" {
		w.Config.WebsocketProtocol = "rust"
	}

	// Without a timeout reverse listeners are never reaped and stay bound after
	// their client is gone; match the CLI default.
	if w.Config.RemoteToLocalServerIdleTimeout == 0 {
		w.Config.RemoteToLocalServerIdleTimeout = 3 * time.Minute
	}

	// Validate has normally refused a bad configuration already; check again
	// because a restriction file can change between validation and provisioning,
	// and NewServer would otherwise carry on with a deny-all placeholder.
	if err := server.ValidateConfig(w.Config); err != nil {
		return fmt.Errorf("wstunnel: %w", err)
	}
	w.server = server.NewServer(w.Config)

	// Merge inline restrictions into the server
	if len(w.Restrictions) > 0 {
		if w.server.GetRules() == nil {
			w.server.SetRules(&server.RestrictionsRules{})
		}
		rules := w.server.GetRules()
		rules.Restrictions = append(rules.Restrictions, w.Restrictions...)
	}

	return nil
}

// Validate checks the configuration before it is provisioned, so a typo makes
// the config load fail instead of producing a handler that quietly does
// something else.
func (w *Wstunnel) Validate() error {
	switch w.Config.WebsocketProtocol {
	case "", "rust", "ws":
	default:
		return fmt.Errorf("wstunnel: unknown mode %q (want rust or ws)", w.Config.WebsocketProtocol)
	}
	if err := server.ValidateConfig(w.Config); err != nil {
		return fmt.Errorf("wstunnel: %w", err)
	}
	return nil
}

// Cleanup runs when Caddy discards this instance, for example on a config
// reload. It ends the tun sessions and reverse-tunnel listeners that belong to
// the old configuration; without it a reload would leave clients connected
// under the rules and limits that were just replaced.
func (w *Wstunnel) Cleanup() error {
	if w.server == nil {
		return nil
	}
	return w.server.Close()
}

// ServeHTTP implements caddyhttp.Handler.
func (w *Wstunnel) ServeHTTP(rw http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// wstunnel-go server handles path prefix checking if configured.

	// We want to detect if this is potentially a wstunnel request.
	// It's either a WebSocket upgrade or an HTTP/2 POST (for h2 transport).

	isWebsocket := strings.ToLower(r.Header.Get("Upgrade")) == "websocket"
	isH2Tunnel := r.ProtoAtLeast(2, 0) && r.Method == http.MethodPost && r.Header.Get("Content-Type") == "application/json"

	if !isWebsocket && !isH2Tunnel {
		return next.ServeHTTP(rw, r)
	}

	// If path prefix is configured, and it doesn't match, pass to next
	if w.Config.PathPrefix != "" {
		expectedPrefix := "/" + w.Config.PathPrefix
		if !strings.HasPrefix(r.URL.Path, expectedPrefix) {
			return next.ServeHTTP(rw, r)
		}
	}

	w.server.ServeHTTP(controllerWriter{rw}, r)
	return nil
}

// controllerWriter restores the optional ResponseWriter interfaces that
// Caddy's writer wrappers hide.
//
// Inside Caddy the handler receives a wrapper (for example
// *caddyhttp.IdleTimeoutWriter) that implements only Unwrap(), the hook used by
// http.ResponseController. wstunnel upgrades a connection by asserting
// http.Hijacker (as do the WebSocket libraries it uses) and streams an HTTP/2
// body by asserting http.Flusher, so against the bare wrapper both fail:
// "response writer does not support hijacking" for WebSocket and an unflushed
// stream for HTTP/2. Routing both through a ResponseController reaches the real
// connection.
type controllerWriter struct {
	http.ResponseWriter
}

// Unwrap lets http.ResponseController keep walking down to the real writer, for
// example to set a write deadline.
func (c controllerWriter) Unwrap() http.ResponseWriter { return c.ResponseWriter }

func (c controllerWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return http.NewResponseController(c.ResponseWriter).Hijack()
}

func (c controllerWriter) Flush() {
	_ = http.NewResponseController(c.ResponseWriter).Flush()
}

// UnmarshalCaddyfile sets up the handler from Caddyfile tokens.
//
//	wstunnel {
//	    mode ws|rust
//	    prefix /v1
//	    restrict_config /path/to/rules.yaml
//	    ping_interval 30s
//	    idle_timeout 60s
//	    mask_frame
//	    restrict_to host:port ...
//	    enable_tun
//	    tun_udp_timeout 30s
//	    tun_max_flows 4096
//	    tun_max_sessions 256
//	    tun_allow 10.0.0.0/8 192.0.2.0/24
//	}
func (w *Wstunnel) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "mode":
				if !d.NextArg() {
					return d.ArgErr()
				}
				w.Config.WebsocketProtocol = d.Val()
			case "prefix":
				if !d.NextArg() {
					return d.ArgErr()
				}
				w.Config.PathPrefix = strings.TrimPrefix(d.Val(), "/")
			case "restrict_config":
				if !d.NextArg() {
					return d.ArgErr()
				}
				w.Config.RestrictConfig = d.Val()
			case "ping_interval":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("invalid ping_interval: %v", err)
				}
				w.Config.WebsocketPingFrequency = dur
			case "idle_timeout":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("invalid idle_timeout: %v", err)
				}
				w.Config.RemoteToLocalServerIdleTimeout = dur
			case "mask_frame":
				w.Config.WebsocketMaskFrame = true
			case "enable_tun":
				w.Config.EnableTun = true
			case "tun_udp_timeout":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("invalid tun_udp_timeout: %v", err)
				}
				w.Config.TunUdpTimeout = dur
			case "tun_max_flows", "tun_max_sessions":
				directive := d.Val()
				if !d.NextArg() {
					return d.ArgErr()
				}
				n, err := strconv.Atoi(d.Val())
				if err != nil || n < 1 {
					return d.Errf("invalid %s %q: want a positive integer", directive, d.Val())
				}
				if directive == "tun_max_flows" {
					w.Config.TunMaxFlows = n
				} else {
					w.Config.TunMaxSessions = n
				}
			case "restrict_to":
				w.Config.RestrictTo = append(w.Config.RestrictTo, d.RemainingArgs()...)
			case "tun_allow":
				args := d.RemainingArgs()
				if len(args) == 0 {
					return d.ArgErr()
				}
				if _, err := server.ParseTunAllow(args); err != nil {
					return d.Err(err.Error())
				}
				w.Config.TunAllow = append(w.Config.TunAllow, args...)
			default:
				return d.Errf("unrecognized subdirective '%s'", d.Val())
			}
		}
	}
	return nil
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Wstunnel)(nil)
	_ caddy.Validator             = (*Wstunnel)(nil)
	_ caddy.CleanerUpper          = (*Wstunnel)(nil)
	_ caddyhttp.MiddlewareHandler = (*Wstunnel)(nil)
	_ caddyfile.Unmarshaler       = (*Wstunnel)(nil)
)
