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
3.  **Server Upgrade:** In `--mode ws`, validates the JWT when a shared secret is configured and otherwise parses an `HS256`-shaped token for compatibility. In `--mode rust`, it parses an `HS256`-shaped token without signature verification to remain wire-compatible with the Rust implementation, then responds with `HTTP/1.1 101 Switching Protocols`.
4.  **Piping:** Both sides enter a loop using the `pkg/tunnel` (Go) or `wstunnel::tunnel::transport::io` (Rust) logic.

### Security Considerations
- **JWT Secrets:** The implementation supports a shared secret (`--jwt-secret`) for signing client tunnel requests and for verifying server-side tunnel JWTs in `--mode ws`.
- **Rust Compatibility:** In `--mode rust`, the server parses `HS256` tunnel JWTs without signature verification so it remains compatible with the original Rust framing behavior.
- **Compatibility Mode:** In `--mode ws`, `--insecure-no-jwt-validation` allows `HS256` tunnel JWTs to be parsed without signature verification after validation would otherwise fail.

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
- `ReverseTcp`, `ReverseUdp`, `ReverseUnix`, `ReverseSocks5`, `ReverseHttpProxy`: reverse tunnels. See [Reverse tunnels](#reverse-tunnels).
- `Tun` (Go-only extension): the connection carries raw IP packets. See [Tun mode](#tun-mode-go-only-extension).

## Reverse tunnels

In a reverse tunnel the server listens and the client connects to the target. The client sends a request whose JWT names the address the server should listen on (`r`, `rp`) and the reverse protocol (`p`). Each request is one connection the server may hand to one visitor, so the client keeps asking: a visitor takes a request, and the client sends the next one.

- **Reverse TCP and Unix.** The server upgrades the request at once and keeps the connection parked. When a visitor arrives it sends an empty binary frame, and the client then dials its target. A Go server advertises this with the `X-Wstunnel-Reverse-Wake` response header. Rust servers answer the request only when a visitor arrives, so a client without the header dials its target straight away.
- **Reverse UDP.** One connection per peer address, one message per datagram, and no wake-up frame: the peer speaks first, so the first datagram wakes the client, which dials a connected UDP socket to the target and forwards it. A peer is dropped after the `timeout` in the `ReverseUdp` claim. A client sends 30 seconds unless `timeout_sec` says otherwise, and `timeout_sec=0` sends no timeout, which means peers never expire (as in Rust). Over WebTransport the stream is framed with a length per datagram, as in forward UDP. Over HTTP/2 UDP travels as a plain byte stream, as in Rust and in forward UDP, so datagram boundaries are best effort there: datagrams sent back to back can merge, and an empty one or one over 32 KiB is not kept apart. Use WebSocket or WebTransport for UDP that depends on boundaries. Rust does not carry an empty datagram over WebSocket either; two Go peers do.
- **Reverse SOCKS5.** The server runs the SOCKS5 listener (with username and password if the claim carries `credentials`). The target is only known after a visitor sends its CONNECT request, so the client's request is held without a reply until then. The reply carries the target in a `Cookie` response header: a JWT, signed with a key derived from the server secret rather than the secret itself so it cannot be replayed as a request (clients read it unchecked), whose `r`/`rp` give the host (bracketed if IPv6) and port and whose `p` is `Tcp` or `Udp`. Over WebTransport the same JWT is sent as a length-prefixed preamble on the stream. The client waits up to 30 seconds for the reply, then asks again. Only CONNECT is supported on a Go server. A held request is dropped from the pool as soon as its client disconnects or gives up, so a visitor is never handed an abandoned one.
- **Reverse HTTP proxy.** Works like reverse SOCKS5, with an HTTP proxy in front: the request is held until a visitor has named a target, and the reply carries it in the same `Cookie` JWT (or preamble over WebTransport). A `CONNECT host[:port]` request names its target (port 443 by default) and is answered `200` once the client has the connection, or `502` if no client could take it. Any other method must carry an absolute URL (port 80 by default); its bytes, and whatever follows, are replayed to the target untouched, so only plain HTTP works that way. With `credentials` in the claim a visitor must send a matching `Proxy-Authorization: Basic` header, or is answered `407` with a `Proxy-Authenticate` challenge.
- **Go extensions.** `X-Wstunnel-Reverse-Ping` (milliseconds) announces that the server pings a parked connection; a client that hears nothing for three intervals drops it and reconnects.

## Tun mode (Go-only extension)

Rust wstunnel has no packet mode and rejects this variant as unknown.

### Claim

`{"p": {"Tun": {"mtu": 1500}}, "r": "0.0.0.0", "rp": 0}`. `mtu` is the client's TUN MTU (1280 to 65535; 0 means 1500). `r` and `rp` are placeholders and ignored.

### Framing

After the handshake the connection carries IP packets:

| Transport | Framing |
|---|---|
| `--mode rust`, `--mode ws` | one binary message per IP packet |
| HTTP/2, WebTransport stream | `[u16 big-endian length][packet]`, as for UDP tunnels |

### Addressing and lifetime

There is no address assignment and no control message. The server terminates each session in its own userspace stack that accepts any source and destination, so every client may use the same inside address (the client defaults to `198.18.0.1` and can be told otherwise with `addr=`, see [TUN.md](TUN.md)). Closing the connection ends the session and all of its flows.

### Server-side forwarding

Each new TCP connection or UDP association is authorized and then dialed as an ordinary outbound connection. A refused TCP flow is answered with RST. ICMP is not forwarded.

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
