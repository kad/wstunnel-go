package client

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The usage guide is the only place operators learn the tun:// syntax, so every
// tun:// argument it shows must actually parse.
func TestTunUsageGuideExamplesParse(t *testing.T) {
	raw, err := os.ReadFile("../../docs/TUN.md")
	if err != nil {
		t.Fatalf("read the usage guide: %v", err)
	}
	re := regexp.MustCompile(`tun://[^\s'"` + "`" + `|]*`)
	var seen int
	for _, m := range re.FindAllString(string(raw), -1) {
		m = strings.TrimRight(m, ".,)")
		if m == "tun://" || strings.HasPrefix(m, "tun://[") {
			continue // the bare scheme mentioned in prose, and the syntax template
		}
		if _, err := ParseTunArg(m); err != nil {
			t.Errorf("docs/TUN.md shows %q but ParseTunArg rejects it: %v", m, err)
		}
		seen++
	}
	if seen < 3 {
		t.Fatalf("found only %d tun:// examples in docs/TUN.md; the extraction regexp is probably wrong", seen)
	}
}

// Every option the parser accepts must be in the options table of the usage
// guide, and the configuration reference must show the full-tunnel options, so
// a new option cannot be added without documenting it.
func TestTunOptionsAreDocumented(t *testing.T) {
	_, err := ParseTunArg("tun://?no-such-option=1")
	if err == nil {
		t.Fatal("unknown option accepted")
	}
	m := regexp.MustCompile(`\(supported: ([^)]*)\)`).FindStringSubmatch(err.Error())
	if m == nil {
		t.Fatalf("cannot read the supported options from %q", err)
	}
	options := strings.Split(m[1], ", ")
	if len(options) < 6 {
		t.Fatalf("options = %v", options)
	}
	tun, err := os.ReadFile("../../docs/TUN.md")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := os.ReadFile("../../docs/CONFIG.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, opt := range options {
		if !strings.Contains(string(tun), "| `"+opt+"` |") {
			t.Errorf("docs/TUN.md has no options-table row for %q", opt)
		}
	}
	// The reference lists the full-tunnel options explicitly.
	for _, want := range []string{"route=default", "routing=", "dns="} {
		if !strings.Contains(string(cfg), want) {
			t.Errorf("docs/CONFIG.md never shows %q", want)
		}
	}
}

// The full-tunnel examples in the usage guide must be full tunnels: they parse,
// ask for route=default and name the routing and DNS they describe.
func TestTunFullTunnelExamplesAreFullTunnels(t *testing.T) {
	raw, err := os.ReadFile("../../docs/TUN.md")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`tun://[^\s'"` + "`" + `|]*route=default[^\s'"` + "`" + `|]*`)
	var seen, withDNS int
	for _, m := range re.FindAllString(string(raw), -1) {
		m = strings.TrimRight(m, ".,)")
		spec, err := ParseTunArg(m)
		if err != nil {
			t.Errorf("%q: %v", m, err)
			continue
		}
		if !spec.FullTunnel || spec.Routing == "" {
			t.Errorf("%q parsed as %+v, want a full tunnel with a routing mode", m, spec)
		}
		seen++
		if len(spec.DNS) > 0 {
			withDNS++
		}
	}
	if seen < 4 || withDNS < 3 {
		t.Fatalf("found %d full-tunnel examples (%d with dns=) in docs/TUN.md; the extraction is probably wrong", seen, withDNS)
	}
}
