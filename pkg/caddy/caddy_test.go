package caddy

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	_ "github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	_ "github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	_ "github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
	"github.com/golang-jwt/jwt/v5"
	"github.com/kad/wstunnel-go/pkg/protocol"
	"github.com/kad/wstunnel-go/pkg/server"
	"github.com/kad/wstunnel-go/pkg/tun"
	"github.com/kad/wstunnel-go/pkg/tun/tuntest"
	"github.com/kad/wstunnel-go/pkg/wst"
)

// adaptCaddyfile runs the real Caddyfile adapter and returns the JSON config.
func adaptCaddyfile(t *testing.T, caddyfileText string) []byte {
	t.Helper()
	adapter := caddyconfig.GetAdapter("caddyfile")
	if adapter == nil {
		t.Fatal("the caddyfile adapter is not registered")
	}
	out, warnings, err := adapter.Adapt([]byte(caddyfileText), nil)
	if err != nil {
		t.Fatalf("adapt: %v\n%s", err, caddyfileText)
	}
	for _, w := range warnings {
		t.Logf("adapter warning: %+v", w)
	}
	return out
}

// findHandler digs the first handler with the given name out of adapted JSON.
func findHandler(t *testing.T, doc []byte, name string) json.RawMessage {
	t.Helper()
	var found json.RawMessage
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if x["handler"] == name && found == nil {
				raw, _ := json.Marshal(x)
				found = raw
				return
			}
			for _, child := range x {
				walk(child)
			}
		case []any:
			for _, child := range x {
				walk(child)
			}
		}
	}
	var root any
	if err := json.Unmarshal(doc, &root); err != nil {
		t.Fatal(err)
	}
	walk(root)
	if found == nil {
		t.Fatalf("no %q handler in the adapted config:\n%s", name, doc)
	}
	return found
}

func TestCaddyfileDirectiveIsRegisteredAndAdapts(t *testing.T) {
	// This is the block the README documents. Before the directive was
	// registered, Caddy rejected it with "wstunnel is not a registered directive".
	doc := adaptCaddyfile(t, `
{
	admin off
}

:18080 {
	route /wstunnel/* {
		wstunnel {
			prefix /wstunnel
			mode ws
			enable_tun
			tun_udp_timeout 45s
			tun_max_flows 100
			tun_max_sessions 7
			tun_allow 10.0.0.0/8 192.0.2.9
			tun_allow 2001:db8::/32
		}
	}
}
`)
	var w Wstunnel
	if err := json.Unmarshal(findHandler(t, doc, "wstunnel"), &w); err != nil {
		t.Fatal(err)
	}
	c := w.Config
	if c.PathPrefix != "wstunnel" || c.WebsocketProtocol != "ws" || !c.EnableTun {
		t.Errorf("config = %+v, want prefix wstunnel, mode ws, tun enabled", c)
	}
	if c.TunUdpTimeout != 45*time.Second || c.TunMaxFlows != 100 || c.TunMaxSessions != 7 {
		t.Errorf("tun limits = %v / %d / %d, want 45s / 100 / 7", c.TunUdpTimeout, c.TunMaxFlows, c.TunMaxSessions)
	}
	if got := strings.Join(c.TunAllow, ","); got != "10.0.0.0/8,192.0.2.9,2001:db8::/32" {
		t.Errorf("tun_allow = %q, want every argument of every directive in order", got)
	}
}

func TestCaddyfileDirectiveWorksWithoutAnOrderLine(t *testing.T) {
	// The README example has an explicit "order wstunnel before reverse_proxy";
	// the module also registers that order itself, so both forms must adapt.
	for name, global := range map[string]string{
		"without order": "{\n\tadmin off\n}",
		"with order":    "{\n\torder wstunnel before reverse_proxy\n\tadmin off\n}",
	} {
		t.Run(name, func(t *testing.T) {
			doc := adaptCaddyfile(t, global+"\n:18080 {\n\twstunnel {\n\t\tmode rust\n\t}\n\treverse_proxy 127.0.0.1:9\n}\n")
			findHandler(t, doc, "wstunnel")

			// wstunnel must run before reverse_proxy, or it never sees its requests.
			s := string(doc)
			if strings.Index(s, `"handler":"wstunnel"`) > strings.Index(s, `"handler":"reverse_proxy"`) {
				t.Fatalf("wstunnel is ordered after reverse_proxy:\n%s", doc)
			}
		})
	}
}

func TestCaddyfileRejectsBadValues(t *testing.T) {
	for name, block := range map[string]string{
		"unknown subdirective": "bogus_option",
		"tun_allow nothing":    "tun_allow",
		"tun_allow bad cidr":   "tun_allow 10.0.0.0/33",
		"tun_allow bad host":   "tun_allow not-an-address",
		"max flows zero":       "tun_max_flows 0",
		"max sessions text":    "tun_max_sessions many",
		"bad duration":         "tun_udp_timeout soon",
	} {
		t.Run(name, func(t *testing.T) {
			adapter := caddyconfig.GetAdapter("caddyfile")
			_, _, err := adapter.Adapt([]byte(":18080 {\n\twstunnel {\n\t\t"+block+"\n\t}\n}\n"), nil)
			if err == nil {
				t.Fatalf("%q was accepted", block)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	for name, tc := range map[string]struct {
		w       Wstunnel
		wantErr string
	}{
		"empty config":    {Wstunnel{}, ""},
		"mode rust":       {Wstunnel{Config: cfg(func(c *serverConfig) { c.WebsocketProtocol = "rust" })}, ""},
		"mode ws":         {Wstunnel{Config: cfg(func(c *serverConfig) { c.WebsocketProtocol = "ws" })}, ""},
		"mode typo":       {Wstunnel{Config: cfg(func(c *serverConfig) { c.WebsocketProtocol = "wss" })}, "unknown mode"},
		"tun_allow ok":    {Wstunnel{Config: cfg(func(c *serverConfig) { c.TunAllow = []string{"10.0.0.0/8"} })}, ""},
		"tun_allow wrong": {Wstunnel{Config: cfg(func(c *serverConfig) { c.TunAllow = []string{"10.0.0.0/99"} })}, "tun_allow"},
	} {
		t.Run(name, func(t *testing.T) {
			err := tc.w.Validate()
			if tc.wantErr == "" && err != nil {
				t.Fatalf("Validate = %v, want nil", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("Validate = %v, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

func TestNonWstunnelRequestsFallThrough(t *testing.T) {
	w := provisioned(t, &Wstunnel{})
	for name, req := range map[string]*http.Request{
		"plain GET":      httptest.NewRequest(http.MethodGet, "/", nil),
		"plain POST":     httptest.NewRequest(http.MethodPost, "/v1/events", strings.NewReader("{}")),
		"JSON over h1.1": jsonPost("/v1/events"),
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			var nextCalled bool
			err := w.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
				nextCalled = true
				return nil
			}))
			if err != nil || !nextCalled {
				t.Fatalf("ServeHTTP = %v, next called = %v; want the request handed on", err, nextCalled)
			}
		})
	}
}

func TestWebsocketOutsideThePrefixFallsThrough(t *testing.T) {
	w := provisioned(t, &Wstunnel{Config: cfg(func(c *serverConfig) { c.PathPrefix = "v1" })})
	req := httptest.NewRequest(http.MethodGet, "/other", nil)
	req.Header.Set("Upgrade", "websocket")
	var nextCalled bool
	_ = w.ServeHTTP(httptest.NewRecorder(), req, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		nextCalled = true
		return nil
	}))
	if !nextCalled {
		t.Fatal("a websocket upgrade outside the configured prefix was not handed to the next handler")
	}
}

// tunSession opens a rust-mode tun session against srv, with the JWT in the
// websocket subprotocol like the real client.
func tunSession(t *testing.T, srv *httptest.Server) (tun.PacketConn, error) {
	t.Helper()
	claims := protocol.JwtTunnelConfig{
		ID:       "caddy-test",
		Protocol: protocol.LocalProtocol{Tun: &protocol.TunProtocol{Mtu: 1500}},
		Remote:   "0.0.0.0",
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("test-secret"))
	if err != nil {
		t.Fatal(err)
	}
	h := http.Header{"Sec-WebSocket-Protocol": {"v1, " + protocol.JwtHeaderPrefix + token}}
	c, _, err := (&wst.Dialer{HandshakeTimeout: 5 * time.Second}).Dial("ws://"+strings.TrimPrefix(srv.URL, "http://")+"/v1/events", h)
	if err != nil {
		return nil, err
	}
	return tun.NewWSTPacketConn(c), nil
}

func echoServer(t *testing.T) netip.AddrPort {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, _ = io.Copy(c, c)
				_ = c.Close()
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).AddrPort()
}

// loopbackRules admits tun sessions and flows to 127.0.0.1, which the built-in
// deny list blocks unless a rule names it.
func loopbackRules(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.yaml")
	const doc = `restrictions:
  - name: tun-loopback
    match:
      - Any
    allow:
      - !Tunnel
        protocol: [Tun]
      - !Tunnel
        protocol: [Tcp, Udp]
        cidr: [127.0.0.1/32]
`
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// caddyWrapper imitates the writer wrappers Caddy puts around the real one: it
// implements Unwrap (for http.ResponseController) and nothing else, so neither
// http.Hijacker nor http.Flusher can be asserted on it.
type caddyWrapper struct {
	rw http.ResponseWriter
}

func (c *caddyWrapper) Header() http.Header         { return c.rw.Header() }
func (c *caddyWrapper) Write(b []byte) (int, error) { return c.rw.Write(b) }
func (c *caddyWrapper) WriteHeader(code int)        { c.rw.WriteHeader(code) }
func (c *caddyWrapper) Unwrap() http.ResponseWriter { return c.rw }

func newTunHandler(t *testing.T, mutate func(*serverConfig)) (*Wstunnel, *httptest.Server) {
	t.Helper()
	w := provisioned(t, &Wstunnel{Config: cfg(func(c *serverConfig) {
		c.PathPrefix = "v1"
		c.EnableTun = true
		c.RestrictConfig = loopbackRules(t)
		if mutate != nil {
			mutate(c)
		}
	})})
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		_ = w.ServeHTTP(&caddyWrapper{rw}, r, caddyhttp.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) error {
			rw.WriteHeader(http.StatusTeapot)
			return nil
		}))
	}))
	t.Cleanup(srv.Close)
	return w, srv
}

func TestTunSessionThroughTheModule(t *testing.T) {
	_, srv := newTunHandler(t, nil)
	pc, err := tunSession(t, srv)
	if err != nil {
		t.Fatalf("tun session: %v", err)
	}
	host := tuntest.NewHost(t, pc, 1500)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := host.DialTCP(ctx, echoServer(t))
	if err != nil {
		t.Fatalf("DialTCP through the module: %v", err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte("through-caddy")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("through-caddy"))
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "through-caddy" {
		t.Fatalf("echo = %q, %v", buf, err)
	}
}

func TestTunIsRefusedUnlessEnabled(t *testing.T) {
	_, srv := newTunHandler(t, func(c *serverConfig) { c.EnableTun = false })
	if pc, err := tunSession(t, srv); err == nil {
		_ = pc.Close()
		t.Fatal("a tun session was accepted although enable_tun is off")
	}
}

func TestTunAllowThroughTheModule(t *testing.T) {
	_, srv := newTunHandler(t, func(c *serverConfig) { c.TunAllow = []string{"10.0.0.0/8"} })
	pc, err := tunSession(t, srv)
	if err != nil {
		t.Fatalf("tun session: %v", err)
	}
	host := tuntest.NewHost(t, pc, 1500)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if c, err := host.DialTCP(ctx, echoServer(t)); err == nil {
		_ = c.Close()
		t.Fatal("a flow outside tun_allow was accepted")
	}
}

func TestCleanupEndsTunSessions(t *testing.T) {
	w, srv := newTunHandler(t, nil)
	pc, err := tunSession(t, srv)
	if err != nil {
		t.Fatalf("tun session: %v", err)
	}
	defer func() { _ = pc.Close() }()

	// Give the session time to be served before the "reload".
	time.Sleep(200 * time.Millisecond)
	if err := w.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := pc.ReadPacket()
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("ReadPacket returned a packet after Cleanup")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a tun session survived Cleanup, so a config reload would leave it running under the old rules")
	}

	if err := w.Cleanup(); err != nil {
		t.Fatalf("second Cleanup: %v", err)
	}
	if pc2, err := tunSession(t, srv); err == nil {
		_ = pc2.Close()
		t.Fatal("a closed module accepted a new tun session")
	}
}

func TestCleanupWithoutProvisionIsSafe(t *testing.T) {
	if err := (&Wstunnel{}).Cleanup(); err != nil {
		t.Fatal(err)
	}
}

// ---- helpers ----

type serverConfig = server.Config

func cfg(mutate func(*serverConfig)) serverConfig {
	var c serverConfig
	mutate(&c)
	return c
}

func jsonPost(path string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}"))
	r.Header.Set("Content-Type", "application/json")
	return r
}

func provisioned(t *testing.T, w *Wstunnel) *Wstunnel {
	t.Helper()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)
	if err := w.Provision(ctx); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() { _ = w.Cleanup() })
	return w
}
