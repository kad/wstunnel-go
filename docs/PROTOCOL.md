# wstunnel Protocol Technical Specification

## Overview
`wstunnel` is a tunneling protocol designed to encapsulate arbitrary layered-4 traffic (TCP, UDP, SOCKS5, HTTP Proxy, Unix Sockets) within a WebSocket or HTTP/2 transport stream. Its primary purpose is to bypass restrictive firewalls and Deep Packet Inspection (DPI) systems by making the tunneled traffic appear as standard web traffic.

## Transport Layer

### WebSocket Framing
The primary transport is WebSocket (RFC 6455). Traffic is encapsulated in **Binary Frames** (Opcode `0x02`).

#### Framing Details:
- **FIN Bit:** Usually set to 1 for each chunk of data.
- **Opcode:** `0x02` (Binary).
- **Payload Length:** Supports standard 7-bit, 16-bit, and 64-bit length encodings.

### HTTP/2 Transport
Alternatively, the protocol supports HTTP/2 as a transport mechanism, utilizing a `POST` request to a specific endpoint (usually `/{prefix}/events`) where the request and response bodies act as a full-duplex stream.

## Tunneling Mechanism

### Connection Establishment (Handshake)
The tunnel configuration is transmitted during the HTTP Upgrade handshake.

#### Custom Handshake Header:
Instead of a separate control plane, `wstunnel` encodes the tunnel instructions within the `Sec-WebSocket-Protocol` header.
- **Format:** `Sec-WebSocket-Protocol: v1, authorization.bearer.<JWT_TOKEN>`
- **Subprotocol:** The version is fixed to `v1`.
- **JWT Claims:** The configuration is a base64-encoded JWT containing:
    - `id`: Unique tunnel identifier (UUID).
    - `p`: Protocol definition (e.g., `{"Tcp": {"proxy_protocol": false}}`).
    - `r`: Remote host to connect to.
    - `rp`: Remote port.

### Data Encapsulation
Once the handshake is complete, the WebSocket becomes a raw pipe. Every byte received from the local listener is wrapped in a WebSocket binary frame and sent to the server. The server unwraps the frame and writes the raw bytes to the destination target.

## Non-Standard Aspects (RFC Deviations)

To improve performance and bypass certain DPI heuristics, `wstunnel` intentionally deviates from RFC 6455 in several ways:

### 1. Relaxed Client Masking
RFC 6455 Section 5.1 requires that all frames sent from a client to a server must be masked.
- **Deviation:** The `wstunnel` server implementation is permissive and **accepts unmasked frames** from the client.
- **Implementation:** The Go implementation (`pkg/wst`) reads the mask bit but does not reject the frame if the bit is 0.

### 2. Zero-Key Masking (Transparent Masking)
- **Deviation:** When masking is enabled on the client side, it may use a fixed "Zero Key" (`0x00000000`).
- **Effect:** This produces a header that is technically compliant with the RFC (mask bit set, 4-byte key present) but the payload itself remains un-obfuscated (XOR with 0 is a no-op). This reduces CPU overhead while satisfying intermediate middleboxes that strictly check for the mask bit.

### 3. JWT Configuration Injection
- **Deviation:** Using the `Sec-WebSocket-Protocol` header to carry structured JSON/JWT configuration is a non-standard use of the subprotocol negotiation field.

## Implementation Details

### Handshake Sequence
1.  **Client Dial:** Performs a TCP/TLS connection to the server.
2.  **Handshake:** Sends a `GET` request with `Upgrade: websocket` and the `Sec-WebSocket-Protocol` containing the JWT.
3.  **Server Upgrade:** Validates the JWT when a shared secret is configured, or parses it without verification when compatibility mode is enabled, and responds with `HTTP/1.1 101 Switching Protocols`.
4.  **Piping:** Both sides enter a loop using the `pkg/tunnel` (Go) or `wstunnel::tunnel::transport::io` (Rust) logic.

### Security Considerations
- **JWT Secrets:** The implementation supports a shared secret (`--jwt-secret`) for signing and verifying tunnel requests.
- **Compatibility Mode:** To support interoperability with clients that do not share a verification secret, the server can be configured to parse JWTs without signature validation (`--insecure-no-jwt-validation`).

### Connection Management
- **Connection Pooling:** The client can maintain a pool of idle WebSocket connections to the server to eliminate the handshake latency for new tunnel requests.
- **Keep-Alive:** Periodic WebSocket `PING/PONG` frames are used to keep connections alive through stateful firewalls.

## API / Protocol Support
The protocol supports the following inner protocols via the `p` claim:
- `tcp`: Standard TCP forwarding.
- `udp`: UDP forwarding with a configurable timeout.
- `socks5`: Dynamic SOCKS5 proxying.
- `http`: HTTP Connect proxying.
- `stdio`: Forwarding to/from stdin/stdout.
- `unix`: Unix domain socket forwarding.

## Examples

### Client Configuration (Go)
```bash
wstunnel-go client -L tcp://1212:google.com:443 --jwt-secret mysecret ws://server:8080
```

### Server Configuration (Go)
```bash
wstunnel-go server ws://0.0.0.0:8080 --jwt-secret mysecret
```

## Testing
Interoperability is verified via `tests/tester/main_test.go`, which runs a matrix of Go-Go, Go-Rust, and Rust-Go combinations, ensuring that the custom `pkg/wst` layer correctly handles the non-standard framing expected by the Rust implementation.
