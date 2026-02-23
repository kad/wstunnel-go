package caddy

import (
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/kad/wstunnel-go/pkg/server"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Wstunnel{})
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

	// If no mode is specified, default to rust for compatibility
	if w.Config.WebsocketProtocol == "" {
		w.Config.WebsocketProtocol = "rust"
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

	w.server.ServeHTTP(rw, r)
	return nil
}

// UnmarshalCaddyfile sets up the handler from Caddyfile tokens.
//
//	wstunnel {
//	    mode ws|rust
//	    prefix /v1
//	    restrict_config /path/to/rules.yaml
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
	_ caddyhttp.MiddlewareHandler = (*Wstunnel)(nil)
	_ caddyfile.Unmarshaler       = (*Wstunnel)(nil)
)
