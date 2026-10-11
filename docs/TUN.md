# Tun mode (packet tunnel)

Tun mode carries IP packets instead of single TCP or UDP streams. The client
creates a TUN device and routes whole subnets into it; the server terminates the
packets in a userspace TCP/IP stack and opens an ordinary outbound connection for
each TCP connection and UDP association it sees. Any program on the client host
can then reach those networks without being configured to use a proxy.

Tun mode is a **Go-only extension**. The Rust `wstunnel` does not implement it
and rejects the `Tun` claim, so both ends must be `wstunnel-go`. Ordinary tunnels
are unaffected and still interoperate with Rust.

## Requirements

- A Linux client. Other platforms report `tun mode is only supported on Linux`.
- On the client, either `CAP_NET_ADMIN` (usually root), or a persistent TUN device
  that an administrator created for your user (see [Without root](#without-root)).
- A server started with `--enable-tun`, and a restriction rule that allows it (see
  [Server setup](#server-setup)).

## Quick start

Server (the rules file is shown below):

```bash
wstunnel-go server --enable-tun --restrict-config rules.yaml wss://0.0.0.0:443
```

Client, as root. Everything addressed to `10.0.0.0/8` now goes through the tunnel:

```bash
wstunnel-go client \
  -L 'tun://wst0?addr=198.18.0.1/32&route=10.0.0.0/8' \
  wss://tunnel.example.com
```

Check it from any program on the client host:

```bash
curl http://10.1.2.3/            # reaches the server's network
ip route show 10.0.0.0/8         # 10.0.0.0/8 dev wst0 scope link
```

## The `tun://` argument

```
tun://[NAME]?addr=PREFIX&route=PREFIX&mtu=N&configure=BOOL
```

| Option | Default | Meaning |
|---|---|---|
| `NAME` | kernel picks `tunN` | Interface name, at most 15 characters. Required with `configure=false`. |
| `addr` | `198.18.0.1/32` and `fd77:7473::1/128` | Address assigned to the device. Repeatable, IPv4 or IPv6. |
| `route` | none | Network routed into the device. Repeatable, IPv4 or IPv6. |
| `mtu` | `1500` | Device MTU, `1280` to `65535`. Sent to the server, which uses the same value. |
| `configure` | `true` | `false` attaches to an existing device and changes nothing. |

Notes:

- The default addresses are in ranges reserved for benchmarking (`198.18.0.0/15`)
  and local use (`fd00::/8`), so they are unlikely to collide with a real network.
  Every client may use the same address: the server keeps each session isolated.
  If the host has IPv6 disabled, the default IPv6 address is skipped with a
  warning; an IPv6 address you ask for explicitly is required.
- Quote the argument in a shell, because `&` is special.
- Only one `tun://` tunnel is allowed per client process, and it works with `-L`
  only. In a YAML config file, list it under `local_to_remote`:

  ```yaml
  mode: client
  client:
    remote_addr: wss://tunnel.example.com
    local_to_remote:
      - "tun://wst0?addr=198.18.0.1/32&route=10.0.0.0/8&route=172.16.0.0/12&mtu=1400"
  ```
- A route that contains the tunnel server's own address is refused at startup:
  the packets that carry the tunnel would be routed back into it and never leave
  the host. Route the networks you want through the tunnel, not the server itself.

## Without root

Creating a device needs `CAP_NET_ADMIN`. Attaching to a persistent device does
not. An administrator creates and configures it once:

```bash
sudo ip tuntap add dev wst0 mode tun user $USER
sudo ip link set wst0 mtu 1400 up
sudo ip addr add 198.18.0.1/32 dev wst0
sudo ip route add 10.0.0.0/8 dev wst0
```

Then run the client as an ordinary user:

```bash
wstunnel-go client -L 'tun://wst0?configure=false' wss://tunnel.example.com
```

With `configure=false` the client reads the device's MTU, sends it to the server,
and never touches addresses, routes or link state.

## Server setup

Tun mode is off unless the server is started with `--enable-tun` (YAML
`enable_tun`, Caddyfile `enable_tun`). The flag is required even when your
restrictions allow every protocol.

A tun session is admitted by a restriction rule that allows the protocol `Tun`.
Each connection inside the session is then checked as a `Tcp` or `Udp` tunnel to
its destination IP and port, against the same rule:

```yaml
restrictions:
  - name: office-network
    match:
      - Any
    allow:
      - !Tunnel
        protocol: [Tun]
      - !Tunnel
        protocol: [Tcp, Udp]
        cidr: [10.0.0.0/8]
```

Put `Tun` in its own `!Tunnel` entry. See [CONFIG.md](CONFIG.md#tun-sessions) for
the details, including the destinations that are always denied unless a rule names
them explicitly (loopback, link-local and cloud metadata addresses).

Server limits, all in [CONFIG.md](CONFIG.md): `tun_max_sessions`, `tun_max_flows`
and `tun_udp_timeout`.

## Behaviour and limits

- **TCP and UDP only.** ICMP is not forwarded, so `ping` through the tunnel does
  not work. DNS works when the resolver is inside a routed network (it is UDP).
- **Reconnects.** If the connection to the server drops, the device and its routes
  stay up and the client reconnects, waiting 1 second and doubling up to 30
  seconds between attempts. While it is down, traffic for the routed networks is
  dropped; it does not leak out of your normal route. Connections that were open
  when the session dropped are reset, and new ones work after the reconnect.
- **Dead peers.** Over the websocket transports (`ws://`, `wss://`, and `--mode ws`) the client pings every `--websocket-ping-frequency` (30 seconds by default) and drops and re-establishes the session if nothing at all arrives from the server within three ping intervals, so a connection silently dropped by a NAT or firewall is replaced in about 90 seconds instead of hanging. HTTP/2 and WebTransport do not send keepalives in this version; a dead connection there is noticed only when the transport itself fails.
- **Transports.** Works over `ws://`, `wss://`, `http://`, `https://`, `wt://` and `wts://`, and with `--mode ws`. The automated tests run tun mode end to end over the websocket (both modes), HTTP/2 and WebTransport transports without TLS; the TLS variants use the same code paths but have no tun-specific test.
- **Not yet supported.** Routing the whole host's traffic (a default route) through
  the tunnel is not supported yet. Only the networks you list as `route` are
  routed.
- **Performance.** Packets are read and written one at a time, without kernel
  offloads, so very high throughput is not a goal of this version.

## Security

In the default `--mode rust` the server does not verify the signature of the
tunnel token, for compatibility with Rust. Anyone who can reach a server started
with `--enable-tun` can open tun sessions, limited only by the restriction rules.
Treat the rules as the access control: allow only the networks that should be
reachable, use `--mode ws` with a `jwt_secret` where you can, and use TLS (and
mTLS, with a rule that matches `ClientCommonName`) on the listener.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `403 Forbidden (is the server started with --enable-tun, ...)` | The server lacks `--enable-tun`, or no rule allows protocol `Tun` for your path or client certificate. |
| `route ... contains the tunnel server ...` | A `route` covers the server's address. Narrow the route. |
| `cannot create or attach tun device ... CAP_NET_ADMIN` | Run as root, or attach to a persistent device with `configure=false`. |
| `configure wst0: set mtu ...: operation not permitted` | You asked the client to configure the device without `CAP_NET_ADMIN`. Use `configure=false`. |
| Connections to a routed network are refused | A rule does not allow that destination. The server logs `tun flow denied` with the destination. |
| Connections hang right after the client starts | The session is still being established; they succeed after the first retry. |
