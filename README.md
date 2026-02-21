# wstunnel-go

A feature-complete Go implementation of [wstunnel](https://github.com/erebe/wstunnel), designed for high performance, ease of use, and library integration.

## Description

`wstunnel-go` allows you to tunnel any traffic through a WebSocket connection, effectively bypassing restrictive firewalls and proxies that only allow HTTP/HTTPS traffic.

This version is a complete port of the original Rust implementation, maintaining full protocol compatibility and CLI parity while offering Go-specific benefits like a modular library design and structured logging with `slog`.

### What to expect:
*   **Protocol Interoperability**: Fully compatible with the original Rust `wstunnel` server and client.
*   **Modular Library**: Can be used as a standalone CLI or integrated into your own Go applications as a library.
*   **High Performance**: Multi-threaded and optimized for low-latency data transfer.
*   **Rich Features**: Supports TCP, UDP, SOCKS5, HTTP Proxy, Stdio, and Unix sockets.
*   **Reverse Tunneling**: Support for both static and dynamic reverse tunnels.
*   **Security**: Supports TLS (wss://), mTLS with client certificates, and YAML-based restriction rules.
*   **Modern Logging**: Uses `log/slog` for structured, level-based logging.

## Command Line Usage

`wstunnel-go` provides a CLI that mirrors the original tool's arguments.

### Client Mode
```bash
wstunnel-go client [OPTIONS] <ws[s]://wstunnel.server.com[:port]>

# Example: Forward local SOCKS5 to remote server
wstunnel-go client -L socks5://127.0.0.1:1080 wss://my-server.com

# Example: Forward local port to remote destination
wstunnel-go client -L tcp://8080:google.com:443 wss://my-server.com
```

### Server Mode
```bash
wstunnel-go server [OPTIONS] [ws[s]://0.0.0.0[:port]]

# Example: Start a basic server
wstunnel-go server --listen 0.0.0.0:8080

# Example: Start server with mTLS and restrictions
wstunnel-go server --tls-certificate cert.pem --tls-private-key key.pem --tls-client-ca-certs ca.pem --restrict-config rules.yaml
```

## Library Usage

You can use `wstunnel-go` as a library in your own project:

```go
import (
    "github.com/kad/wstunnel-go/pkg/client"
    "github.com/kad/wstunnel-go/pkg/protocol"
)

func main() {
    config := client.Config{
        ServerURL: "wss://my-server.com",
        // ... other config
    }
    c := client.NewClient(config)
    
    ltr := &protocol.LocalToRemote{
        Local: "127.0.0.1:1080",
        Protocol: protocol.LocalProtocol{
            Socks5: &protocol.Socks5Protocol{},
        },
    }
    
    c.StartTunnel(ltr)
}
```

## How to Build

Ensure you have Go 1.21+ installed.

```bash
cd wstunnel-go
go build ./cmd/wstunnel-go
./wstunnel-go --help
```

## Status & Interoperability

| Feature | Status | Interop |
| :--- | :---: | :---: |
| TCP Forward/Reverse | ✅ | ✅ |
| UDP Forward/Reverse | ✅ | ✅ |
| SOCKS5 Forward | ✅ | ✅ |
| SOCKS5 Reverse | ✅ | ⚠️ (Basic) |
| HTTP Proxy (CONNECT) | ✅ | ✅ |
| Unix Sockets | ✅ | ✅ |
| Stdio Tunneling | ✅ | ✅ |
| YAML Restrictions | ✅ | ✅ |
| mTLS | ✅ | ✅ |
| HTTP/2 Transport | ❌ | - |

⚠️ *Note: Reverse SOCKS5 is functional but uses a simplified handshake compared to the Rust version.*

## License

Same as the original project. See [LICENSE](../LICENSE).
