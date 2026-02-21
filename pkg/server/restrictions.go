package server

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/kad/wstunnel-go/pkg/protocol"
	"gopkg.in/yaml.v3"
)

type RestrictionsRules struct {
	Restrictions []RestrictionConfig `yaml:"restrictions"`
}

type RestrictionConfig struct {
	Name  string        `yaml:"name"`
	Match []MatchConfig `yaml:"match"`
	Allow []AllowConfig `yaml:"allow"`
}

type MatchConfig struct {
	Any           bool
	PathPrefix    *regexp.Regexp
	Authorization *regexp.Regexp
}

func (m *MatchConfig) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err == nil {
		if s == "Any" {
			m.Any = true
			return nil
		}
	}

	var res struct {
		PathPrefix    string `yaml:"PathPrefix"`
		Authorization string `yaml:"Authorization"`
	}
	if err := value.Decode(&res); err != nil {
		return err
	}

	if res.PathPrefix != "" {
		re, err := regexp.Compile(res.PathPrefix)
		if err != nil {
			return err
		}
		m.PathPrefix = re
	}
	if res.Authorization != "" {
		re, err := regexp.Compile(res.Authorization)
		if err != nil {
			return err
		}
		m.Authorization = re
	}
	return nil
}

type AllowConfig struct {
	Tunnel        *AllowTunnelConfig
	ReverseTunnel *AllowReverseTunnelConfig
}

func (a *AllowConfig) UnmarshalYAML(value *yaml.Node) error {
	if value.Tag == "!Tunnel" {
		a.Tunnel = &AllowTunnelConfig{}
		return value.Decode(a.Tunnel)
	}
	if value.Tag == "!ReverseTunnel" {
		a.ReverseTunnel = &AllowReverseTunnelConfig{}
		return value.Decode(a.ReverseTunnel)
	}
	return fmt.Errorf("unknown allow tag: %s", value.Tag)
}

type AllowTunnelConfig struct {
	Protocol []string    `yaml:"protocol"`
	Port     []PortRange `yaml:"port"`
	Host     *Regexp     `yaml:"host"`
	CIDR     []NetCIDR   `yaml:"cidr"`
}

type AllowReverseTunnelConfig struct {
	Protocol    []string          `yaml:"protocol"`
	Port        []PortRange       `yaml:"port"`
	PortMapping map[uint16]uint16 `yaml:"port_mapping"`
	CIDR        []NetCIDR         `yaml:"cidr"`
	UnixPath    *Regexp           `yaml:"unix_path"`
}

type NetCIDR struct {
	*net.IPNet
}

func (n *NetCIDR) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		return err
	}
	n.IPNet = ipnet
	return nil
}

type PortRange struct {
	Min uint16
	Max uint16
}

func (p *PortRange) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	if strings.Contains(s, "..") {
		parts := strings.Split(s, "..")
		min, _ := strconv.ParseUint(parts[0], 10, 16)
		max, _ := strconv.ParseUint(parts[1], 10, 16)
		p.Min = uint16(min)
		p.Max = uint16(max)
	} else {
		val, _ := strconv.ParseUint(s, 10, 16)
		p.Min = uint16(val)
		p.Max = uint16(val)
	}
	return nil
}

type Regexp struct {
	*regexp.Regexp
}

func (r *Regexp) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	re, err := regexp.Compile(s)
	if err != nil {
		return err
	}
	r.Regexp = re
	return nil
}

func LoadRestrictions(path string) (*RestrictionsRules, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	rules := &RestrictionsRules{}
	if err := yaml.Unmarshal(data, rules); err != nil {
		return nil, err
	}
	return rules, nil
}

func (r *RestrictionsRules) Validate(claims *protocol.JwtTunnelConfig, path string, auth string) bool {
	if r == nil || len(r.Restrictions) == 0 {
		return true
	}

	for _, restr := range r.Restrictions {
		if restr.Matches(path, auth) {
			if restr.Allows(claims) {
				return true
			}
		}
	}
	return false
}

func (rc *RestrictionConfig) Matches(path string, auth string) bool {
	for _, m := range rc.Match {
		if m.Any {
			return true
		}
		if m.PathPrefix != nil && m.PathPrefix.MatchString(path) {
			return true
		}
		if m.Authorization != nil && m.Authorization.MatchString(auth) {
			return true
		}
	}
	return false
}

func (rc *RestrictionConfig) Allows(claims *protocol.JwtTunnelConfig) bool {
	isReverse := claims.Protocol.ReverseTcp != nil || claims.Protocol.ReverseUdp != nil ||
		claims.Protocol.ReverseSocks5 != nil || claims.Protocol.ReverseHttpProxy != nil ||
		claims.Protocol.ReverseUnix != nil

	for _, a := range rc.Allow {
		if isReverse && a.ReverseTunnel != nil {
			if a.ReverseTunnel.Allows(claims) {
				return true
			}
		} else if !isReverse && a.Tunnel != nil {
			if a.Tunnel.Allows(claims) {
				return true
			}
		}
	}
	return false
}

func (at *AllowTunnelConfig) Allows(claims *protocol.JwtTunnelConfig) bool {
	// Protocol
	if len(at.Protocol) > 0 {
		proto := getProtoName(claims.Protocol)
		found := false
		for _, p := range at.Protocol {
			if strings.EqualFold(p, proto) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Port
	if len(at.Port) > 0 {
		found := false
		for _, pr := range at.Port {
			if claims.Port >= pr.Min && claims.Port <= pr.Max {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Host
	if at.Host != nil && !at.Host.MatchString(claims.Remote) {
		return false
	}

	// CIDR
	if len(at.CIDR) > 0 {
		ip := net.ParseIP(claims.Remote)
		if ip != nil {
			found := false
			for _, c := range at.CIDR {
				if c.Contains(ip) {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		} else if at.Host == nil {
			// If not an IP and no host regex, but CIDRs are set, fail
			return false
		}
	}

	return true
}

func (art *AllowReverseTunnelConfig) Allows(claims *protocol.JwtTunnelConfig) bool {
	// Protocol
	if len(art.Protocol) > 0 {
		proto := getProtoName(claims.Protocol)
		found := false
		for _, p := range art.Protocol {
			if strings.EqualFold(p, proto) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Unix path
	if claims.Protocol.ReverseUnix != nil {
		if art.UnixPath != nil && !art.UnixPath.MatchString(claims.Protocol.ReverseUnix.Path) {
			return false
		}
		return true
	}

	// Port
	if len(art.Port) > 0 {
		found := false
		for _, pr := range art.Port {
			if claims.Port >= pr.Min && claims.Port <= pr.Max {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// CIDR
	if len(art.CIDR) > 0 {
		ip := net.ParseIP(claims.Remote)
		if ip != nil {
			found := false
			for _, c := range art.CIDR {
				if c.Contains(ip) {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
	}

	return true
}

func getProtoName(p protocol.LocalProtocol) string {
	if p.Tcp != nil {
		return "Tcp"
	}
	if p.Udp != nil {
		return "Udp"
	}
	if p.Socks5 != nil {
		return "Socks5"
	}
	if p.HttpProxy != nil {
		return "Http"
	}
	if p.Unix != nil {
		return "Unix"
	}
	if p.ReverseTcp != nil {
		return "ReverseTcp"
	}
	if p.ReverseUdp != nil {
		return "ReverseUdp"
	}
	if p.ReverseSocks5 != nil {
		return "ReverseSocks5"
	}
	if p.ReverseHttpProxy != nil {
		return "ReverseHttp"
	}
	if p.ReverseUnix != nil {
		return "ReverseUnix"
	}
	return "Unknown"
}
