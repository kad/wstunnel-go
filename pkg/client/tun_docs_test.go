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
		switch m {
		case "tun://[NAME]?addr=PREFIX&route=PREFIX&mtu=N&configure=BOOL", "tun://":
			continue // the syntax template, and the bare scheme mentioned in prose
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
