package protocol

import (
	"encoding/json"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const JwtHeaderPrefix = "authorization.bearer."

type LocalProtocol struct {
	Tcp              *TcpProtocol              `json:"Tcp,omitempty"`
	Udp              *UdpProtocol              `json:"Udp,omitempty"`
	Stdio            *StdioProtocol            `json:"Stdio,omitempty"`
	Socks5           *Socks5Protocol           `json:"Socks5,omitempty"`
	TProxyTcp        *struct{}                 `json:"TProxyTcp,omitempty"`
	TProxyUdp        *TProxyUdpProtocol        `json:"TProxyUdp,omitempty"`
	HttpProxy        *HttpProxyProtocol        `json:"HttpProxy,omitempty"`
	ReverseTcp       *struct{}                 `json:"ReverseTcp,omitempty"`
	ReverseUdp       *ReverseUdpProtocol       `json:"ReverseUdp,omitempty"`
	ReverseSocks5    *ReverseSocks5Protocol    `json:"ReverseSocks5,omitempty"`
	ReverseHttpProxy *ReverseHttpProxyProtocol `json:"ReverseHttpProxy,omitempty"`
	ReverseUnix      *ReverseUnixProtocol      `json:"ReverseUnix,omitempty"`
	Unix             *UnixProtocol             `json:"Unix,omitempty"`
}

type TcpProtocol struct {
	ProxyProtocol bool `json:"proxy_protocol"`
}

type UdpProtocol struct {
	Timeout *Duration `json:"timeout,omitempty"`
}

type StdioProtocol struct {
	ProxyProtocol bool `json:"proxy_protocol"`
}

type Socks5Protocol struct {
	Timeout     *Duration    `json:"timeout,omitempty"`
	Credentials *Credentials `json:"credentials,omitempty"`
}

type TProxyUdpProtocol struct {
	Timeout *Duration `json:"timeout,omitempty"`
}

type HttpProxyProtocol struct {
	Timeout       *Duration    `json:"timeout,omitempty"`
	Credentials   *Credentials `json:"credentials,omitempty"`
	ProxyProtocol bool         `json:"proxy_protocol"`
}

type ReverseUdpProtocol struct {
	Timeout *Duration `json:"timeout,omitempty"`
}

type ReverseSocks5Protocol struct {
	Timeout     *Duration    `json:"timeout,omitempty"`
	Credentials *Credentials `json:"credentials,omitempty"`
}

type ReverseHttpProxyProtocol struct {
	Timeout     *Duration    `json:"timeout,omitempty"`
	Credentials *Credentials `json:"credentials,omitempty"`
}

type ReverseUnixProtocol struct {
	Path string `json:"path"`
}

type UnixProtocol struct {
	Path          string `json:"path"`
	ProxyProtocol bool   `json:"proxy_protocol"`
}

type Duration struct {
	Secs  uint64 `json:"secs"`
	Nanos uint32 `json:"nanos"`
}

type Credentials struct {
	Username string
	Password string
}

func (c Credentials) MarshalJSON() ([]byte, error) {
	return json.Marshal([]string{c.Username, c.Password})
}

func (c *Credentials) UnmarshalJSON(data []byte) error {
	var arr []string
	if err := json.Unmarshal(data, &arr); err != nil {
		return err
	}
	if len(arr) == 2 {
		c.Username = arr[0]
		c.Password = arr[1]
	}
	return nil
}

type JwtTunnelConfig struct {
	ID            string        `json:"id"`
	Protocol      LocalProtocol `json:"p"`
	Remote        string        `json:"r"`
	Port          uint16        `json:"rp"`
	jwt.MapClaims `json:"-"`
}

// Implement jwt.Claims interface manually to avoid extra fields in JSON
func (j JwtTunnelConfig) GetExpirationTime() (*jwt.NumericDate, error) { return nil, nil }
func (j JwtTunnelConfig) GetIssuedAt() (*jwt.NumericDate, error)       { return nil, nil }
func (j JwtTunnelConfig) GetNotBefore() (*jwt.NumericDate, error)      { return nil, nil }
func (j JwtTunnelConfig) GetIssuer() (string, error)                   { return "", nil }
func (j JwtTunnelConfig) GetSubject() (string, error)                  { return "", nil }
func (j JwtTunnelConfig) GetAudience() (jwt.ClaimStrings, error)       { return nil, nil }

type LocalToRemote struct {
	Protocol LocalProtocol
	Local    string // bind address for local, or path for unix
	Remote   string // remote host
	Port     uint16 // remote port
}

func NewDuration(d time.Duration) *Duration {
	return &Duration{
		Secs:  uint64(d.Seconds()),
		Nanos: uint32(d.Nanoseconds() % 1e9),
	}
}

func (d *Duration) ToTimeDuration() time.Duration {
	return time.Duration(d.Secs)*time.Second + time.Duration(d.Nanos)*time.Nanosecond
}
