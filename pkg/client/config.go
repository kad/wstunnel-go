package client

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kad/wstunnel-go/pkg/protocol"
)

func parseDurationSec(s string) (*protocol.Duration, error) {
	if s == "" {
		return nil, nil
	}
	d, err := time.ParseDuration(s + "s")
	if err != nil {
		// Try parsing as raw int
		secs, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return nil, err
		}
		return &protocol.Duration{Secs: secs}, nil
	}
	return &protocol.Duration{Secs: uint64(d.Seconds()), Nanos: uint32(d.Nanoseconds() % 1e9)}, nil
}

func ParseTunnelArg(arg string, isReverse bool) (*protocol.LocalToRemote, error) {
	parts := strings.SplitN(arg, "://", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid tunnel format, missing ://")
	}
	proto := parts[0]
	info := parts[1]

	// Split by '?' to get options
	options := make(map[string]string)
	if idx := strings.Index(info, "?"); idx != -1 {
		query := info[idx+1:]
		info = info[:idx]
		values, _ := url.ParseQuery(query)
		for k, v := range values {
			if len(v) > 0 {
				options[k] = v[0]
			}
		}
	}

	getTimeout := func() *protocol.Duration {
		if val, ok := options["timeout_sec"]; ok {
			d, _ := parseDurationSec(val)
			return d
		}
		return &protocol.Duration{Secs: 30}
	}

	getCredentials := func() *protocol.Credentials {
		login := options["login"]
		pass := options["password"]
		if login != "" && pass != "" {
			return &protocol.Credentials{Username: login, Password: pass}
		}
		return nil
	}

	getProxyProtocol := func() bool {
		_, ok := options["proxy_protocol"]
		return ok
	}

	// For stdio, it is protocol://host:port
	if proto == "stdio" {
		host, portStr, err := net.SplitHostPort(info)
		if err != nil {
			return nil, fmt.Errorf("invalid stdio target: %w", err)
		}
		port, _ := strconv.ParseUint(portStr, 10, 16)
		return &protocol.LocalToRemote{
			Protocol: protocol.LocalProtocol{
				Stdio: &protocol.StdioProtocol{ProxyProtocol: getProxyProtocol()},
			},
			Remote: host,
			Port:   uint16(port),
		}, nil
	}

	if proto == "unix" {
		parts := strings.SplitN(info, ":", 2)
		path := parts[0]
		ltr := &protocol.LocalToRemote{
			Local: path,
		}
		if len(parts) > 1 {
			remoteInfo := parts[1]
			rHost, rPortStr, err := net.SplitHostPort(remoteInfo)
			if err == nil {
				rPort, _ := strconv.ParseUint(rPortStr, 10, 16)
				ltr.Remote = rHost
				ltr.Port = uint16(rPort)
			}
		}
		if isReverse {
			ltr.Protocol = protocol.LocalProtocol{ReverseUnix: &protocol.ReverseUnixProtocol{Path: path}}
		} else {
			ltr.Protocol = protocol.LocalProtocol{Unix: &protocol.UnixProtocol{Path: path, ProxyProtocol: getProxyProtocol()}}
		}
		return ltr, nil
	}

	// Format is usually [bind:]port[:host:port]
	localBind := "127.0.0.1"
	localPort := ""
	remoteHost := "0.0.0.0"
	var remotePort uint16

	parts_info := strings.Split(info, ":")
	switch len(parts_info) {
	case 1: // port
		localPort = parts_info[0]
	case 2: // bind:port OR port:host (ambiguous, assume bind:port for dynamic, port:host if we had a way to know)
		// wstunnel usually treats it as bind:port if it's dynamic
		localBind = parts_info[0]
		localPort = parts_info[1]
	case 3: // port:host:port
		localPort = parts_info[0]
		remoteHost = parts_info[1]
		rp, _ := strconv.ParseUint(parts_info[2], 10, 16)
		remotePort = uint16(rp)
	case 4: // bind:port:host:port
		localBind = parts_info[0]
		localPort = parts_info[1]
		remoteHost = parts_info[2]
		rp, _ := strconv.ParseUint(parts_info[3], 10, 16)
		remotePort = uint16(rp)
	default:
		return nil, fmt.Errorf("invalid tunnel format: %s", info)
	}

	ltr := &protocol.LocalToRemote{
		Local:  net.JoinHostPort(localBind, localPort),
		Remote: remoteHost,
		Port:   remotePort,
	}

	switch proto {
	case "tcp":
		if isReverse {
			ltr.Protocol = protocol.LocalProtocol{ReverseTcp: &struct{}{}}
		} else {
			ltr.Protocol = protocol.LocalProtocol{Tcp: &protocol.TcpProtocol{ProxyProtocol: getProxyProtocol()}}
		}
	case "udp":
		if isReverse {
			ltr.Protocol = protocol.LocalProtocol{ReverseUdp: &protocol.ReverseUdpProtocol{Timeout: getTimeout()}}
		} else {
			ltr.Protocol = protocol.LocalProtocol{Udp: &protocol.UdpProtocol{Timeout: getTimeout()}}
		}
	case "socks5":
		if isReverse {
			ltr.Protocol = protocol.LocalProtocol{ReverseSocks5: &protocol.ReverseSocks5Protocol{Timeout: getTimeout(), Credentials: getCredentials()}}
		} else {
			ltr.Protocol = protocol.LocalProtocol{Socks5: &protocol.Socks5Protocol{Timeout: getTimeout(), Credentials: getCredentials()}}
		}
	case "http":
		if isReverse {
			ltr.Protocol = protocol.LocalProtocol{ReverseHttpProxy: &protocol.ReverseHttpProxyProtocol{Timeout: getTimeout(), Credentials: getCredentials()}}
		} else {
			ltr.Protocol = protocol.LocalProtocol{HttpProxy: &protocol.HttpProxyProtocol{Timeout: getTimeout(), Credentials: getCredentials(), ProxyProtocol: getProxyProtocol()}}
		}
	case "tproxy+tcp":
		ltr.Protocol = protocol.LocalProtocol{TProxyTcp: &struct{}{}}
	case "tproxy+udp":
		ltr.Protocol = protocol.LocalProtocol{TProxyUdp: &protocol.TProxyUdpProtocol{Timeout: getTimeout()}}
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", proto)
	}

	return ltr, nil
}
