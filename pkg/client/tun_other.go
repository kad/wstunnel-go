//go:build !linux

package client

import (
	"errors"
	"net/netip"
)

var errTunUnsupported = errors.New("tun mode is only supported on Linux")

func openTunDevice(string) (tunDevice, error) { return nil, errTunUnsupported }

func deviceMTU(string) (int, error) { return 0, errTunUnsupported }

func newNetConfigurer() netConfigurer { return unsupportedConfigurer{} }

type unsupportedConfigurer struct{}

func (unsupportedConfigurer) SetMTU(string, int) error            { return errTunUnsupported }
func (unsupportedConfigurer) AddAddr(string, netip.Prefix) error  { return errTunUnsupported }
func (unsupportedConfigurer) LinkUp(string) error                 { return errTunUnsupported }
func (unsupportedConfigurer) AddRoute(string, netip.Prefix) error { return errTunUnsupported }
