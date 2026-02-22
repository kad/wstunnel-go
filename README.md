# wstunnel-go

A feature-complete Go implementation of [wstunnel](https://github.com/erebe/wstunnel), designed for high performance, ease of use, and library integration.

`wstunnel-go` allows you to tunnel any traffic through a WebSocket or HTTP/2 connection, effectively bypassing restrictive firewalls and proxies that only allow HTTP/HTTPS traffic.

## Features

- **Protocol Support**: TCP, UDP, SOCKS5 (with auth), HTTP Proxy (CONNECT, with auth), Unix domain sockets, and Stdio.
- **TProxy Support**: Transparent proxying for TCP and UDP on Linux.
- **Reverse Tunneling**: Support for both static and dynamic reverse tunnels.
- **Transports**: Secure WebSocket (default) or full-duplex streaming over HTTP/2.
- **Security**: 
  - TLS (wss://) with certificate verification.
  - mTLS with client certificates.
  - ECH (Encrypted Client Hello) and SNI (Server Name Indication) override/disable.
  - JWT-based authentication (fully compatible with Rust version).
  - YAML-based restriction rules for server-side control.
- **Modern Architecture**:
  - Fully multi-threaded using Go's efficient goroutines.
  - Structured logging with `log/slog`.
  - Modular library design for easy integration into other Go projects.
  - Proxy Protocol support for preserving client IP through proxies.
- **Interoperability**: Maintains full protocol compatibility and CLI parity with the original Rust implementation.

## Installation

### Prerequisites

- **Go version 1.25** or above.
- `make` (optional, for convenient building).

### Build from Source

```bash
git clone https://github.com/kad/wstunnel-go.git
cd wstunnel-go
make build
# Binary will be available in ./bin/wstunnel-go
```

Alternatively, using standard Go commands:

```bash
go build -o wstunnel-go ./cmd/wstunnel-go
```

## Usage

### Client Mode

`wstunnel-go` provides a CLI that mirrors the original tool's arguments.

```bash
# Forward local SOCKS5 to remote server
wstunnel-go client -L socks5://127.0.0.1:1080 wss://my-server.com

# Forward local port to remote destination
wstunnel-go client -L tcp://8080:google.com:443 wss://my-server.com

# Use HTTP/2 transport
wstunnel-go client -L tcp://8080:google.com:443 https://my-server.com
```

### Server Mode

```bash
# Start a basic server listening on port 8080
wstunnel-go server ws://0.0.0.0:8080

# Start server with mTLS and restriction rules
wstunnel-go server --tls-certificate cert.pem --tls-private-key key.pem --tls-client-ca-certs ca.pem --restrict-config rules.yaml
```

## Configuration

`wstunnel-go` can be configured via command-line flags, environment variables, or a YAML configuration file.

### YAML Configuration Example

```yaml
mode: client # or server
log_lvl: INFO
no_color: false
client:
  remote_addr: wss://my-server.com
  local_to_remote:
    - "tcp://8080:google.com:443"
    - "socks5://127.0.0.1:1080"
server:
  remote_addr: ws://0.0.0.0:8080
  restrict_config: /etc/wstunnel/rules.yaml
```

Run with config file:
```bash
wstunnel-go --config my-config.yaml
```

## API Reference (Library Usage)

You can use `wstunnel-go` as a library in your own project:

```go
import (
    "github.com/kad/wstunnel-go/pkg/client"
    "github.com/kad/wstunnel-go/pkg/protocol"
)

func main() {
    config := client.Config{
        ServerURL: "wss://my-server.com",
        Transport: "websocket",
        // ... other config
    }
    c := client.NewClient(config)
    
    ltr := &protocol.LocalToRemote{
        Local: "127.0.0.1:1080",
        Protocol: protocol.LocalProtocol{
            Socks5: &protocol.Socks5Protocol{},
        },
    }
    
    go c.StartTunnel(ltr)
    select {}
}
```

## Status & Interoperability

| Feature | Status | Interop (Rust) |
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
| HTTP/2 Transport | ✅ | ✅ |
| TProxy (Linux) | ✅ | ✅ |

⚠️ *Note: Reverse SOCKS5 is functional but uses a simplified handshake compared to the Rust version.*

### Performance Metrics

*Benchmarks are currently being finalized and will be published here once complete.*

## Contributing

Contributions are welcome! Please ensure you follow the project's coding standards:
1.  Run `make fmt` to format code.
2.  Run `make lint` and `make vet` for static analysis.
3.  Ensure all tests pass with `make test`.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.