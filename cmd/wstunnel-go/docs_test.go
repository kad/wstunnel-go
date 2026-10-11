package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/kad/wstunnel-go/pkg/client"
	"github.com/kad/wstunnel-go/pkg/server"
	"go.yaml.in/yaml/v3"
)

// docFlagNames returns every flag name and alias defined in main.go.
func docFlagNames(t *testing.T) map[string]bool {
	t.Helper()
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{"help": true, "h": true}
	for _, m := range regexp.MustCompile(`Name:\s+"([A-Za-z0-9-]+)"`).FindAllStringSubmatch(string(src), -1) {
		names[m[1]] = true
	}
	for _, m := range regexp.MustCompile(`Aliases:\s+\[\]string\{([^}]*)\}`).FindAllStringSubmatch(string(src), -1) {
		for _, a := range regexp.MustCompile(`"([^"]+)"`).FindAllStringSubmatch(m[1], -1) {
			names[a[1]] = true
		}
	}
	return names
}

// shellWords splits a command line the way a POSIX shell would for the simple
// cases the docs use: single and double quotes and backslash-newline joins.
func shellWords(line string) []string {
	var words []string
	var cur strings.Builder
	inWord := false
	var quote rune
	for _, r := range line {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote, inWord = r, true
		case r == ' ' || r == '\t':
			if inWord {
				words = append(words, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			cur.WriteRune(r)
			inWord = true
		}
	}
	if inWord {
		words = append(words, cur.String())
	}
	return words
}

// checkCommand validates one documented wstunnel-go invocation against the real
// flag names, the position of --config, and the tun:// argument parser.
func checkCommand(t *testing.T, where string, words []string, flags map[string]bool) {
	t.Helper()
	i := 0
	for i < len(words) && words[i] != "wstunnel-go" && !strings.HasSuffix(words[i], "/wstunnel-go") {
		i++
	}
	if i == len(words) {
		return
	}
	words = words[i+1:]
	sub := ""
	for j := 0; j < len(words); j++ {
		w := words[j]
		if !strings.HasPrefix(w, "-") {
			if sub == "" && (w == "client" || w == "server") {
				sub = w
			}
			continue
		}
		name := strings.TrimLeft(w, "-")
		name, _, hasValue := strings.Cut(name, "=")
		if !flags[name] {
			t.Errorf("%s: unknown flag %q in: %s", where, w, strings.Join(words, " "))
			continue
		}
		if name == "config" && sub != "" {
			t.Errorf("%s: --config must come before %q, it is a global option: %s", where, sub, strings.Join(words, " "))
		}
		if name == "L" || name == "local-to-remote" {
			arg := ""
			if hasValue {
				_, arg, _ = strings.Cut(w, "=")
			} else if j+1 < len(words) {
				arg = words[j+1]
			}
			if client.IsTunArg(arg) {
				if _, err := client.ParseTunArg(arg); err != nil {
					t.Errorf("%s: tun argument %q does not parse: %v", where, arg, err)
				}
			}
		}
	}
	if sub == "" {
		// Only "wstunnel-go --config FILE" without a subcommand is a complete command.
		hasConfig := false
		for _, w := range words {
			hasConfig = hasConfig || w == "--config"
		}
		if !hasConfig {
			t.Errorf("%s: no client or server subcommand in: %s", where, strings.Join(words, " "))
		}
	}
}

func docBlocks(t *testing.T, path, lang string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	fence := regexp.MustCompile("(?s)```" + lang + "\n(.*?)```")
	var out []string
	for _, m := range fence.FindAllStringSubmatch(string(raw), -1) {
		out = append(out, m[1])
	}
	return out
}

// commandLines joins backslash continuations and drops comments and blank lines.
func commandLines(block string) []string {
	block = strings.ReplaceAll(block, "\\\n", " ")
	var out []string
	for _, l := range strings.Split(block, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		out = append(out, l)
	}
	return out
}

func TestDocumentedCommandsUseRealFlags(t *testing.T) {
	flags := docFlagNames(t)
	var checked int
	for _, doc := range []string{"../../README.md", "../../docs/TUN.md", "../../docs/CONFIG.md"} {
		for bi, block := range docBlocks(t, doc, "bash") {
			for _, line := range commandLines(block) {
				// Only the lines that start a wstunnel-go invocation (optionally via sudo).
				if !strings.HasPrefix(line, "wstunnel-go ") && !strings.HasPrefix(line, "sudo wstunnel-go ") {
					continue
				}
				checkCommand(t, fmt.Sprintf("%s bash block %d", doc, bi+1), shellWords(line), flags)
				checked++
			}
		}
	}
	// The ExecStart lines of the shipped units and of the unit snippets in TUN.md.
	units, err := filepath.Glob("../../packaging/systemd/*.service")
	if err != nil || len(units) == 0 {
		t.Fatalf("no unit files found: %v", err)
	}
	var execLines []struct{ where, line string }
	for _, u := range units {
		raw, err := os.ReadFile(u)
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range strings.Split(string(raw), "\n") {
			if v, ok := strings.CutPrefix(l, "ExecStart="); ok {
				execLines = append(execLines, struct{ where, line string }{u, v})
			}
		}
	}
	for _, block := range docBlocks(t, "../../docs/TUN.md", "ini") {
		for _, l := range strings.Split(block, "\n") {
			if v, ok := strings.CutPrefix(l, "ExecStart="); ok {
				execLines = append(execLines, struct{ where, line string }{"docs/TUN.md ini", v})
			}
		}
	}
	for _, e := range execLines {
		checkCommand(t, e.where, shellWords(e.line), flags)
		checked++
	}
	if checked < 12 {
		t.Fatalf("checked only %d commands; the extraction is probably wrong", checked)
	}
}

// strictConfig decodes like loadConfigFile but rejects keys the structs do not know.
func strictConfig(data []byte) (*FullConfig, error) {
	cfg := &FullConfig{}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func checkDocumentedConfig(t *testing.T, where string, data []byte) {
	t.Helper()
	cfg, err := strictConfig(data)
	if err != nil {
		t.Errorf("%s does not load: %v\n%s", where, err, data)
		return
	}
	// The real loader must agree.
	path := filepath.Join(t.TempDir(), "cfg.yaml")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfigFile(path); err != nil {
		t.Errorf("%s: loadConfigFile: %v", where, err)
	}
	if cfg.Client != nil {
		if cfg.Client.ServerURL == "" {
			t.Errorf("%s: client has no remote_addr", where)
		}
		for _, arg := range cfg.Client.LocalToRemote {
			if client.IsTunArg(arg) {
				if _, err := client.ParseTunArg(arg); err != nil {
					t.Errorf("%s: %q: %v", where, arg, err)
				}
			} else if _, err := client.ParseTunnelArg(arg, false); err != nil {
				t.Errorf("%s: %q: %v", where, arg, err)
			}
		}
		for _, arg := range cfg.Client.RemoteToLocal {
			if _, err := client.ParseTunnelArg(arg, true); err != nil {
				t.Errorf("%s: %q: %v", where, arg, err)
			}
		}
	}
	if cfg.Server != nil {
		if _, err := server.ParseTunAllow(cfg.Server.TunAllow); err != nil {
			t.Errorf("%s: tun_allow: %v", where, err)
		}
		if cfg.Server.ListenAddr == "" {
			t.Errorf("%s: server has no listen_addr", where)
		}
	}
}

func TestDocumentedYAMLLoads(t *testing.T) {
	var checked, rules int
	for _, doc := range []string{"../../README.md", "../../docs/TUN.md", "../../docs/CONFIG.md"} {
		for i, block := range docBlocks(t, doc, "yaml") {
			where := fmt.Sprintf("%s yaml block %d", doc, i+1)
			switch {
			case strings.HasPrefix(block, "mode:"):
				checkDocumentedConfig(t, where, []byte(block))
				checked++
			case strings.HasPrefix(block, "restrictions:"):
				path := filepath.Join(t.TempDir(), "rules.yaml")
				if err := os.WriteFile(path, []byte(block), 0o600); err != nil {
					t.Fatal(err)
				}
				if _, err := server.LoadRestrictions(path); err != nil {
					t.Errorf("%s does not load as restrictions: %v\n%s", where, err, block)
				}
				rules++
			}
		}
	}
	if checked < 4 || rules < 1 {
		t.Fatalf("checked %d configs and %d rule sets; the extraction is probably wrong", checked, rules)
	}
}

func TestPackagedExamplesLoad(t *testing.T) {
	files, err := filepath.Glob("../../packaging/examples/*.yaml")
	if err != nil || len(files) < 5 {
		t.Fatalf("examples = %v, %v", files, err)
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.HasPrefix(data, []byte("restrictions:")) {
			if _, err := server.LoadRestrictions(f); err != nil {
				t.Errorf("%s: %v", f, err)
			}
			continue
		}
		checkDocumentedConfig(t, f, data)
	}
}
