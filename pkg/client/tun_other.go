//go:build !linux

package client

import (
	"errors"
	"net/netip"
)

var errTunUnsupported = errors.New("tun mode is only supported on Linux")

func openTunDevice(string, bool) (tunDevice, error) { return nil, errTunUnsupported }

func deviceMTU(string) (int, error) { return 0, errTunUnsupported }

func newNetConfigurer() netConfigurer { return unsupportedConfigurer{} }

type unsupportedConfigurer struct{}

func (unsupportedConfigurer) SetMTU(string, int) error            { return errTunUnsupported }
func (unsupportedConfigurer) AddAddr(string, netip.Prefix) error  { return errTunUnsupported }
func (unsupportedConfigurer) LinkUp(string) error                 { return errTunUnsupported }
func (unsupportedConfigurer) AddRoute(string, netip.Prefix) error { return errTunUnsupported }
func (unsupportedConfigurer) DelRoute(string, netip.Prefix) error { return errTunUnsupported }
func (unsupportedConfigurer) AddTableRoute(string, netip.Prefix, int) error {
	return errTunUnsupported
}
func (unsupportedConfigurer) DelTableRoute(string, netip.Prefix, int) error {
	return errTunUnsupported
}
func (unsupportedConfigurer) AddHostRoute(netip.Prefix, netip.Addr, string) error {
	return errTunUnsupported
}
func (unsupportedConfigurer) DelHostRoute(netip.Prefix, netip.Addr, string) error {
	return errTunUnsupported
}
func (unsupportedConfigurer) AddRule(ruleSpec) error            { return errTunUnsupported }
func (unsupportedConfigurer) DelRule(ruleSpec) error            { return errTunUnsupported }
func (unsupportedConfigurer) ListRules(int) ([]ruleSpec, error) { return nil, errTunUnsupported }
func (unsupportedConfigurer) RouteGet(netip.Addr, string) (routeInfo, error) {
	return routeInfo{}, errTunUnsupported
}

func rpFilterOf(string) (int, error) { return 0, errTunUnsupported }
