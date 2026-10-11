package caddy

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig"
)

// The Caddyfile examples in the documentation were once unusable without
// anyone noticing, because nothing ever fed them to Caddy. Adapt every one.
func TestDocumentedCaddyfilesAdapt(t *testing.T) {
	fence := regexp.MustCompile("(?s)```caddyfile\n(.*?)```")
	adapter := caddyconfig.GetAdapter("caddyfile")
	if adapter == nil {
		t.Fatal("the caddyfile adapter is not registered")
	}

	var checked int
	for _, path := range []string{"../../README.md", "../../docs/CONFIG.md", "../../docs/TUN.md"} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for i, m := range fence.FindAllStringSubmatch(string(raw), -1) {
			block := dedent(m[1])
			// A bare "wstunnel { ... }" snippet is only valid inside a site.
			if strings.HasPrefix(strings.TrimSpace(block), "wstunnel") {
				block = ":18080 {\n\troute /wstunnel/* {\n" + indent(block, "\t\t") + "\t}\n}\n"
			}
			if _, _, err := adapter.Adapt([]byte(block), nil); err != nil {
				t.Errorf("%s caddyfile block %d does not adapt: %v\n%s", path, i+1, err, block)
			}
			checked++
		}
	}
	if checked < 5 {
		t.Fatalf("found only %d caddyfile blocks in the docs; the extraction is probably wrong", checked)
	}
}

// dedent removes the common leading whitespace of the non-empty lines.
func dedent(s string) string {
	lines := strings.Split(s, "\n")
	common := -1
	for _, l := range lines {
		if strings.TrimSpace(l) == "" {
			continue
		}
		n := len(l) - len(strings.TrimLeft(l, " \t"))
		if common < 0 || n < common {
			common = n
		}
	}
	if common <= 0 {
		return s
	}
	for i, l := range lines {
		if len(l) >= common {
			lines[i] = l[common:]
		}
	}
	return strings.Join(lines, "\n")
}

func indent(s, prefix string) string {
	var b strings.Builder
	for _, l := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		if strings.TrimSpace(l) == "" {
			b.WriteString("\n")
			continue
		}
		b.WriteString(prefix + l + "\n")
	}
	return b.String()
}
