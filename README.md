# wstunnel-go

A feature-complete Go implementation of [wstunnel](https://github.com/erebe/wstunnel), designed for high performance, ease of use, and library integration.

`wstunnel-go` allows you to tunnel any traffic through a WebSocket or HTTP/2 connection, effectively bypassing restrictive firewalls and proxies that only allow HTTP/HTTPS traffic.

## Features

-   **Protocol Support**:
    -   **TCP**: Reliable stream tunneling.
    -   **UDP**: Datagram tunneling with state tracking.
    -   **SOCKS5**: Local SOCKS5 proxy (with optional authentication).
    -   **HTTP Proxy**: Local HTTP CONNECT proxy (with optional authentication).
    -   **Unix Domain Sockets**: Tunneling to/from local unix sockets.
    -   **Stdio**: Tunneling via standard input/output.
-   **TProxy Support**: Transparent proxying for TCP and UDP on Linux (requires root/CAP_NET_ADMIN).
-   **Reverse Tunneling**: Stable support for static reverse TCP and reverse Unix socket tunnels (server-to-client).
-   **Transports**:
    -   **WebSocket-like transport**: Secure WebSocket-style transport (default) with intentional RFC 6455 deviations for compatibility with the original Rust implementation.
    -   **RFC 6455 compliant WebSocket**: Enable strict RFC 6455 compliance with `--mode ws` (compatible with standard Go clients).
    -   **HTTP/2**: Full-duplex streaming over HTTP/2.
-   **Deployment**:
    -   **Systemd**: Ready-to-use systemd unit templates for Linux.
    -   **Windows Task Scheduler**: PowerShell scripts for easy deployment as a background task on Windows.
    -   **Docker**: (Coming soon) Ready-to-use Docker images.
-   **Security**:
    -   **TLS (wss://, https://)**: Full TLS support with certificate verification.
    -   **mTLS**: Support for client certificates and private keys.
    -   **ECH (Encrypted Client Hello)**: Enable ECH for enhanced privacy.
    -   **SNI Control**: Override or disable Server Name Indication.
    -   **JWT Authentication**: Fully compatible with the original Rust implementation's JWT-based auth.
    -   **Restriction Rules**: Server-side YAML configuration to restrict allowed tunnel destinations and path prefixes.
-   **Advanced Networking**:
    -   **SO_MARK**: (Linux only) Support for marking outgoing packets.
    -   **DNS Control**: Custom DNS resolvers and IPv4/IPv6 preference.
    -   **Proxy Support**: Connect through HTTP/HTTPS proxies (with authentication).
    -   **Proxy Protocol**: Support for Proxy Protocol (v1/v2) to preserve client IP.
-   **Modern Architecture**:
    -   **Highly Concurrent**: Leverages Go's goroutines for efficient handling of many simultaneous tunnels.
    -   **Structured Logging**: Uses `log/slog` for modern, structured logging.
    -   **Library First**: Designed as a library for easy integration into other Go projects.
-   **Interoperability**: Maintains full protocol compatibility and CLI parity with the original Rust implementation.

## Installation

### Prerequisites

-   **Go version 1.25** or above.
-   `make` (optional, for convenient building).

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

### Download Pre-built Binaries and Packages

Binaries for various platforms (Linux, macOS, Windows) and distribution packages (`.deb`, `.rpm`, `.apk`) are available on the [Releases](https://github.com/kad/wstunnel-go/releases) page.

### Installation via Package Manager (Linux)

For Debian/Ubuntu-based systems:
```bash
sudo dpkg -i wstunnel-go_amd64.deb
```

### Systemd Integration (Linux)

`wstunnel-go` provides systemd template units for easy management of client and server instances.

1.  Place your configuration YAML file in `/etc/wstunnel-go/client-myserver.yaml`.
2.  Enable and start the service:
    ```bash
    sudo systemctl enable --now wstunnel-go-client@myserver
    ```

For the server:
1.  Place your configuration YAML file in `/etc/wstunnel-go/server-main.yaml`.
2.  Enable and start the service:
    ```bash
    sudo systemctl enable --now wstunnel-go-server@main
    ```

### Windows Task Scheduler Integration

Use the provided PowerShell scripts in the `packaging/windows` directory to register `wstunnel-go` as a background task.

```powershell
# In an elevated PowerShell session:
.\packaging\windows\install.ps1 -ConfigPath "C:\path\to\your\client.yaml" -BinaryPath "C:\path\to\wstunnel-go.exe"

# Control the task:
.\packaging\windows\control.ps1 -Action start
```

### Caddy Integration (Server)

`wstunnel-go` can be built into Caddy server as an HTTP handler.

1.  Build Caddy with `wstunnel-go` module:
    ```bash
    xcaddy build --with github.com/kad/wstunnel-go/pkg/caddy
    ```

2.  Configure in `Caddyfile`:
    ```caddyfile
    {
        order wstunnel before reverse_proxy
    }

    example.com {
        route /wstunnel/* {
            wstunnel {
                prefix /wstunnel
                mode rust
                # restrict_config /etc/wstunnel/rules.yaml
            }
        }
    }
    ```

`wstunnel-go` in Caddy automatically leverages Caddy's TLS termination, including mTLS.

## Usage

### Client Mode

`wstunnel-go` provides a CLI that mirrors the original tool's arguments.

```bash
# Forward local SOCKS5 to remote server
wstunnel-go client -L socks5://127.0.0.1:1080 wss://my-server.com

# Forward local port to remote destination
wstunnel-go client -L tcp://8080:google.com:443 wss://my-server.com

# Reverse tunnel: remote server port 8080 forwards to local 127.0.0.1:80
wstunnel-go client -R tcp://8080:127.0.0.1:80 wss://my-server.com

# Use HTTP/2 transport
wstunnel-go client -L tcp://8080:google.com:443 https://my-server.com

# Use custom DNS resolver and prefer IPv4
wstunnel-go client --dns-resolver 8.8.8.8 --dns-resolver-prefer-ipv4 -L tcp://8080:google.com:443 wss://my-server.com
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

### CLI Flags

#### Global Flags
-   `--config`: Path to YAML configuration file.
-   `--log-lvl`: Log verbosity (TRACE, DEBUG, INFO, WARN, ERROR, OFF). Default: INFO.
-   `--no-color`: Disable color output.
-   `--nb-worker-threads`: Number of worker threads (environment variable: `TOKIO_WORKER_THREADS`).

#### Client Flags
-   `-L, --local-to-remote`: Define a local-to-remote tunnel.
-   `-R, --remote-to-local`: Define a remote-to-local (reverse) tunnel.
-   `--http-upgrade-path-prefix`: HTTP upgrade path prefix (default: "v1").
-   `--jwt-secret`: Shared secret used to sign tunnel JWTs.
-   `--http-upgrade-credentials`: Basic auth credentials for upgrade request.
-   `-H, --header`: Custom HTTP headers for upgrade request.
-   `--http-headers-file`: File containing custom HTTP headers.
-   `--tls-verify-certificate`: Enable/disable TLS cert verification.
-   `--tls-sni-override`: Override SNI domain.
-   `--tls-sni-disable`: Disable sending SNI.
-   `--tls-ech-enable`: Enable ECH.
-   `--http-proxy`: Use an HTTP proxy for the connection.
-   `--connection-min-idle`: Maintain a pool of idle connections.
-   `--connection-retry-max-backoff`: Maximum retry backoff for server connection.
-   `--dns-resolver`: Custom DNS resolver(s).
-   `--dns-resolver-prefer-ipv4`: Prioritize IPv4 for DNS lookup.
-   `--websocket-ping-frequency`: Frequency of WebSocket pings.
-   `--websocket-mask-frame`: Enable masking of WebSocket frames.

#### Server Flags
-   `--restrict-to`: Restrict tunnels to specific destinations.
-   `-r, --restrict-http-upgrade-path-prefix`: Restrict tunnels to specific path prefixes.
-   `--jwt-secret`: Shared secret used to verify tunnel JWTs.
-   `--insecure-no-jwt-validation`: Allow unverified tunnel JWTs for compatibility.
-   `--restrict-config`: Path to a YAML file with restriction rules.
-   `--tls-certificate`, `--tls-private-key`: Paths to TLS cert/key for the server.
-   `--tls-client-ca-certs`: Enable mTLS by providing CA certificates to verify clients.
-   `--remote-to-local-server-idle-timeout`: Idle timeout for reverse tunnel server.

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
  listen_addr: ws://0.0.0.0:8080
  restrict_config: /etc/wstunnel/rules.yaml
```

## API Reference (Library Usage)

`wstunnel-go` is built with a modular design, making it easy to use as a library.

```go
import (
    "github.com/kad/wstunnel-go/pkg/client"
    "github.com/kad/wstunnel-go/pkg/protocol"
)

func main() {
    config := client.Config{
        ServerURL: "wss://my-server.com",
        PathPrefix: "v1",
        // ... other config
    }
    c := client.NewClient(config)

    ltr, _ := client.ParseTunnelArg("tcp://8080:google.com:443", false)
    go c.StartTunnel(ltr)

    select {}
}
```

## Status & Interoperability

`wstunnel-go` aims for 100% parity with the [Rust version](https://github.com/erebe/wstunnel).

| Feature | Status | Interop (Rust) |
| :--- | :---: | :---: |
| TCP Forward/Reverse | ✅ | ✅ |
| UDP Forward | ✅ | ✅ |
| UDP Reverse | ❌ | ❌ |
| SOCKS5 Forward | ✅ | ✅ |
| SOCKS5 Reverse | ❌ | ❌ |
| HTTP Proxy (CONNECT) | ✅ | ✅ |
| Reverse HTTP Proxy | ❌ | ❌ |
| Unix Sockets | ✅ | ✅ |
| Stdio Tunneling | ✅ | ✅ |
| YAML Restrictions | ✅ | ✅ |
| mTLS | ✅ | ✅ |
| HTTP/2 Transport | ✅ | ✅ |
| TProxy (Linux) | ✅ | ✅ |
| JWT Authentication | ✅ | ✅ |

### Performance Metrics

| Metric | wstunnel (Rust) | wstunnel-go |
| :--- | :---: | :---: |
| Throughput (TCP) | ~ Gbps | ~ Gbps |
| Latency Overhead | < 1ms | < 1ms |
| Memory Usage (Idle) | ~ 10MB | ~ 20MB |

*Note: Benchmarks are environment-dependent. Go version typically shows slightly higher memory usage due to GC and goroutine stacks, but comparable throughput.*

### Compatibility Versions

-   **Rust wstunnel**: v9.0.0+
-   **Go**: 1.25+

## Contributing

Contributions are welcome! Please ensure you follow the project's coding standards:
1.  Run `make fmt` to format code.
2.  Run `make lint` and `make vet` for static analysis.
3.  Ensure all tests pass with `make test`.
4.  Run `make test-interop` if you change protocol-related code.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
