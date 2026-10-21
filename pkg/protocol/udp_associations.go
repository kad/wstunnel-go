package protocol

import (
	"net"
	"sync"
)

// UDPAssociations records the addresses that have an authenticated SOCKS5 UDP
// association open: the senders a UDP relay of a credential-protected listener
// may serve. RFC 1928 ties a relay to the client that asked for it, and a relay
// that served anyone who could reach its port would be an open proxy for a
// listener that asks for a password. The sender's port is not compared, since
// the ASSOCIATE request usually does not know it.
type UDPAssociations struct {
	mu  sync.Mutex
	ips map[string]int
}

func ipKey(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

// Add records an association for ip and returns the function that ends it.
func (a *UDPAssociations) Add(ip net.IP) (release func()) {
	k := ipKey(ip)
	a.mu.Lock()
	if a.ips == nil {
		a.ips = make(map[string]int)
	}
	a.ips[k]++
	a.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			a.mu.Lock()
			defer a.mu.Unlock()
			if a.ips[k]--; a.ips[k] <= 0 {
				delete(a.ips, k)
			}
		})
	}
}

// Allows reports whether ip has an association open.
func (a *UDPAssociations) Allows(ip net.IP) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.ips[ipKey(ip)] > 0
}

// AddrIP returns the IP of a network address.
func AddrIP(addr net.Addr) net.IP {
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.IP
	case *net.TCPAddr:
		return a.IP
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}
