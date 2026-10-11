//go:build linux

package client

import (
	"net"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestRuleFromNetlinkReadsSelectors(t *testing.T) {
	full := ^uint32(0)
	part := uint32(0xff)
	_, n10, _ := net.ParseCIDR("10.0.0.0/8")
	mk := func(f func(r *netlink.Rule)) netlink.Rule {
		r := netlink.NewRule()
		r.Priority, r.Table = 32761, 30580
		r.Mark, r.Mask, r.Invert = 30580, &full, true
		f(r)
		return *r
	}
	for name, tc := range map[string]struct {
		rule        netlink.Rule
		wantForeign string
	}{
		"ours":         {mk(func(*netlink.Rule) {}), ""},
		"src":          {mk(func(r *netlink.Rule) { r.Src = n10 }), "from 10.0.0.0/8"},
		"dst":          {mk(func(r *netlink.Rule) { r.Dst = n10 }), "to 10.0.0.0/8"},
		"iif":          {mk(func(r *netlink.Rule) { r.IifName = "eth0" }), "iif eth0"},
		"oif":          {mk(func(r *netlink.Rule) { r.OifName = "eth0" }), "oif eth0"},
		"partial mask": {mk(func(r *netlink.Rule) { r.Mask = &part }), "mask"},
		"tos":          {mk(func(r *netlink.Rule) { r.Tos = 4 }), "tos"},
		"ipproto":      {mk(func(r *netlink.Rule) { r.IPProto = 6 }), "ipproto"},
		"uidrange":     {mk(func(r *netlink.Rule) { r.UIDRange = netlink.NewRuleUIDRange(0, 10) }), "uidrange"},
		"goto":         {mk(func(r *netlink.Rule) { r.Goto = 5 }), "goto"},
		"dport":        {mk(func(r *netlink.Rule) { r.Dport = netlink.NewRulePortRange(22, 22) }), "dport"},
		"not unicast":  {mk(func(r *netlink.Rule) { r.Type = 7 }), "type"},
	} {
		t.Run(name, func(t *testing.T) {
			got := ruleFromNetlink(4, tc.rule)
			if tc.wantForeign == "" {
				if got.Selectors != "" {
					t.Fatalf("our own rule reported selectors %q", got.Selectors)
				}
				return
			}
			if got.Selectors == "" || !strings.Contains(got.Selectors, tc.wantForeign) {
				t.Fatalf("Selectors = %q, want it to mention %q", got.Selectors, tc.wantForeign)
			}
		})
	}
}
