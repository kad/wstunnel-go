package client

import (
	"slices"
	"strings"
	"testing"
)

// A rule at one of our priorities that carries selectors we do not set (or any
// other unexpected attribute) is foreign even when its table and mark match.
func TestClassifyRulesTreatsSelectorsAsForeign(t *testing.T) {
	ours := fullTunnelRules(4, 0x7774)
	withSel := func(r ruleSpec) ruleSpec { r.Selectors = "from 10.0.0.0/8"; return r }
	existing := []ruleSpec{withSel(ours[0]), withSel(ours[1])}
	stale, conflict := classifyRules(existing, 0x7774)
	if len(stale) != 0 || !slices.Equal(conflict, existing) {
		t.Fatalf("stale=%v conflict=%v, want both as conflicts", stale, conflict)
	}
	nl := &recordingConfigurer{existingRules: slices.Clone(existing)}
	err := purgeStaleRules(nl, 0x7774)
	if err == nil || !strings.Contains(err.Error(), "from 10.0.0.0/8") {
		t.Fatalf("purge = %v, want a refusal that names the selector", err)
	}
	if !slices.Equal(nl.existingRules, existing) {
		t.Fatalf("a foreign rule was deleted: %v", nl.existingRules)
	}
}
