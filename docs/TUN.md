# Tun mode (packet tunnel)

Tun mode carries IP packets instead of single TCP or UDP streams. The client
creates a TUN device and routes whole subnets into it; the server terminates the
packets in a userspace TCP/IP stack and opens an ordinary outbound connection for
each TCP connection and UDP association it sees. Any program on the client host
can then reach those networks without being configured to use a proxy. With
`route=default` the whole host's IPv4 and IPv6 traffic goes through the tunnel
(see [Full tunnel](#full-tunnel-routedefault)).

Tun mode is a **Go-only extension**. The Rust `wstunnel` does not implement it
and rejects the `Tun` claim, so both ends must be `wstunnel-go`. Ordinary tunnels
are unaffected and still interoperate with Rust.

## Requirements

- A Linux client. Other platforms report `tun mode is only supported on Linux`.
- On the client, either `CAP_NET_ADMIN` (usually root), or a persistent TUN device
  that an administrator created for your user (see [Without root](#without-root)).
  The full tunnel (`route=default`) installs rules and routes itself, so it always
  needs `CAP_NET_ADMIN`; that is the only capability the routing needs (for `dns=` see the
  notes under [Deployment](#deployment)). It also never uses a
  persistent device: it refuses a device name that already exists.
- A server started with `--enable-tun`, and a restriction rule that allows it (see
  [Server setup](#server-setup)).

## Quick start

Server (the rules file is shown below):

```bash
wstunnel-go server --enable-tun --restrict-config rules.yaml \
  --tls-certificate cert.pem --tls-private-key key.pem wss://0.0.0.0:443
```

The server turns on TLS only when it is given a certificate and key; the `wss://` scheme alone does not enable it. The certificate must be valid for the host name the clients use. The rules file is the one shown under [Server setup](#server-setup), saved as `rules.yaml`.

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
tun://[NAME]?addr=PREFIX&route=PREFIX|default&routing=auto|fwmark|pin&dns=ADDR&mtu=N&configure=BOOL
```

| Option | Default | Meaning |
|---|---|---|
| `NAME` | kernel picks `tunN` | Interface name, at most 15 characters. Required with `configure=false`. |
| `addr` | `198.18.0.1/32` and `fd77:7473::1/128` | Address assigned to the device. Repeatable, IPv4 or IPv6. |
| `route` | none | Network routed into the device. Repeatable, IPv4 or IPv6. `default` routes all IPv4 and IPv6 traffic and must be the only `route` (see [Full tunnel](#full-tunnel-routedefault)). |
| `routing` | `auto` | Only with `route=default`: how the tunnel's own traffic avoids the tunnel. `auto`, `fwmark` or `pin`. |
| `dns` | none | Only with `route=default`: DNS server (an IP address, repeatable) set on the device through `resolvectl`. Needs `configure=true`. |
| `mtu` | `1500` | Device MTU, `1280` to `65535`. Sent to the server, which uses the same value. |
| `configure` | `true` | `false` attaches to an existing device and changes nothing. Not allowed with `route=default` or `dns`. |

Notes:

- The default addresses are in ranges reserved for benchmarking (`198.18.0.0/15`)
  and local use (`fd00::/8`), so they are unlikely to collide with a real network.
  Every client may use the same address: the server keeps each session isolated.
  If the host has IPv6 disabled, the default IPv6 address is skipped with a
  warning; an IPv6 address you ask for explicitly is required.
- Quote the argument in a shell, because `&` is special.
- The parser is strict: an empty `mtu=`, `configure=` or `routing=`, a repeated
  `mtu`, `configure` or `routing`, a device name with control characters, an
  IPv4-mapped IPv6 prefix such as `::ffff:10.0.0.0/104`, an `addr` of `/0` and a
  `;` separator are all errors. The `tun://` scheme must be lower case. Option
  names and values (`routing=pin`, not `PIN`) are case-sensitive.
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
  The server name is resolved again before every reconnect and the check is
  repeated, so a DNS answer that moves the server into a routed network stops the
  reconnect (traffic stays dropped) instead of looping. If the name cannot be
  resolved at that moment the last addresses that passed the check are used.
- An `addr` shorter than a host prefix (for example `198.18.0.1/24`) also makes
  the kernel route that whole network into the device, so the same check applies
  to it. The defaults, `/32` and `/128`, are right for almost everyone.

## Full tunnel (`route=default`)

`route=default` sends all of the host's IPv4 and IPv6 traffic through the tunnel.
Routes that are more specific than the default (your LAN, a VPN, the loopback
network) keep working as before. It needs `configure=true` and `CAP_NET_ADMIN`,
and `route=default` cannot be combined with other `route=` values.

The server rule must admit the destinations you want, for example `cidr:
[0.0.0.0/0, ::/0]`; the built-in deny list (loopback, link-local, metadata
addresses) still applies. See [Server setup](#server-setup).

The hard part is the tunnel's own connection to the server: if the default route
points at the TUN, that connection would be routed into the tunnel too. There are
two ways around it, chosen by `routing=`.

| `routing` | How the tunnel's own traffic bypasses the TUN |
|---|---|
| `fwmark` | The client marks its own sockets (and its own DNS lookups of the server name) with a firewall mark. The mark is `--socket-so-mark` if you set it, otherwise `0x7774` (30580). The same number is the routing table id. Table 30580 holds `default dev <tun>` for IPv4 and IPv6. Two rules per family: priority 32760 `lookup main suppress_prefixlength 0` (so more specific main-table routes still win) and priority 32761 `not fwmark <mark> lookup <mark>`. |
| `pin` | A host route (`/32` or `/128`) to every address of the server through the real gateway and device, found with a route lookup that ignores the tunnel's own routes, plus the four halves `0.0.0.0/1`, `128.0.0.0/1`, `::/1` and `8000::/1` through the TUN, which override the default route without removing it. The pins are deleted and looked up again before every reconnect, so a changed gateway or a changed DNS answer is followed. |
| `auto` (default) | `fwmark`, unless the reverse-path filter would break it, then `pin`. |

### Why there are two modes: rp_filter

Measured with three network namespaces (client and app, a gateway holding the
server that does not forward, a target reachable only through the server), with
the server reached through the client's default route, which is the normal case:

| Mode | `rp_filter` off or loose (0, 2) | `rp_filter` strict (1) |
|---|---|---|
| `fwmark` (rules above, own sockets marked) | works | **fails**: the server's replies are dropped, the session never comes up |
| `pin` | works | works |

Under strict filtering the kernel checks that a packet's source would be routed
back out of the interface it arrived on. That check ignores the socket mark, so
for the server's reply it consults the rule that sends unmarked traffic to the
TUN, finds the TUN, and drops the reply. A host route to the server hides the
problem (the check then finds that route), which is why `pin` is immune.

`auto` therefore reads the effective setting for the route to the server, which
is the larger of `net.ipv4.conf.all.rp_filter` and the egress interface's own
setting (the kernel takes the maximum), and picks `pin` when it is `1`. IPv6 has
no such sysctl. If the setting cannot be read, `auto` assumes it is strict and
picks `pin`, because `pin` works either way.

An explicit `routing=fwmark` with strict filtering is refused at startup, before
anything is changed:

```
routing=fwmark cannot work here: strict reverse-path filtering (rp_filter=1) is
active for the route to the tunnel server 192.0.2.10, and it would drop the
server's replies; use routing=pin or routing=auto, or relax it with:
sysctl -w net.ipv4.conf.all.rp_filter=2 (and the same for the egress interface,
whichever is higher counts)
```

If the setting cannot be read, an explicit `fwmark` starts with a warning, since
it cannot be shown to fail.

No sysctl is changed by the client.

### DNS

`dns=ADDR` (repeatable, IP addresses without a zone) makes the client run

```
resolvectl dns <tun> ADDR...
resolvectl domain <tun> '~.'
```

so systemd-resolved sends every name to those servers over the tunnel. The client
does this after the device is up and before the routing is installed. Each command
has a 10 second limit, and a failure or timeout is a warning only: the tunnel
still starts, without the DNS settings. Whether `resolvectl` is permitted for the
user and capabilities the client runs with depends on systemd-resolved's polkit
policy (see the systemd notes under [Deployment](#deployment)). Without
`resolvectl` the client warns and leaves DNS alone. It never edits
`/etc/resolv.conf`. systemd-resolved forgets the settings when the device goes
away; the client also runs `resolvectl revert <tun>` on exit, which only matters
for a device that outlives it.

Resolving the tunnel server's own name is a chicken-and-egg problem while the
tunnel is down. Before every connect a full tunnel resolves the name again (in
`fwmark` mode through a resolver whose sockets carry the mark). If that fails, the
last addresses that passed the loop check are used, and if there never were any the
client does not connect. Whichever addresses result are what the connection is
actually made to, on every transport (the Rust-compatible and RFC 6455 websockets,
HTTP/2 over TCP, and WebTransport over QUIC): the addresses are tried in order and
the first that connects wins (the 10 second dial deadline is shared out, so an address that silently drops packets gets its share, at least 2 seconds, and the next one is still tried), while the host name from the server URL is still what
TLS sends as SNI and verifies, what the HTTP `Host` and websocket URL carry. So a
reconnect works while DNS is unreachable. This applies to `route=default` only; a
partial-route tun tunnel re-resolves for the loop check but dials by name. A server
given by IP address avoids the question. If the resolver on the host is a local stub
(systemd-resolved at `127.0.0.53`) that `~.` now sends through the tunnel, the name
lookup depends on the tunnel being up and the cached addresses carry the reconnects.

### Cleanup and crash recovery

On SIGINT, SIGTERM, SIGHUP or a fatal device error the client removes the rules, the
table 30580 routes and the pinned host routes it installed, then exits (the TUN
device and its `/1` and default routes disappear with the device). A forced kill
(SIGKILL, power loss) cannot clean up. What it leaves is harmless: with the device
gone, table 30580 is empty, so lookups fall through to the main table and the host
keeps its normal routing; a stale pin is a correct route to the server. The next
start in fwmark mode deletes the leftover rules at priorities 32760 and 32761 before
installing its own (it logs `Removed a stale rule`). It deletes only the suppress
rule at 32760 and the `not fwmark <mark>` rule at 32761 for its own mark; rules at
any other priority, including the 32764/32765 pair that wg-quick installs, are never
touched. If a different rule sits at 32760 or 32761 (a stale rule of another fwmark,
or another full tunnel), the client refuses to start and tells you to remove it with
`ip rule del`. A rule at those priorities that also matches on a source, destination,
interface, port, partial mask or anything else our rules never use is treated as
someone else's, even if its mark and table are ours: the client refuses and never
deletes it. Pin mode installs no rules and never reads or deletes any. Nothing is
stored on disk.

Only one fwmark full-tunnel client can run per host. A second one refuses to start
in two ways: with the same mark it cannot take the lock file
`/run/wstunnel-go-tun-<mark>.lock` (in the temp directory when `/run` is not
writable), which a running client holds with an exclusive `flock` for its whole
life (`another full tunnel with mark ... is running (pid N)`); with another mark it
finds the first one's rules at 32760/32761 and refuses as described above. The
lock is released when the client stops, and also when it is killed, which is why
the rules a crashed client left behind are known to be stale and are purged. The
lock file itself stays on disk (empty of meaning once unlocked); it is not
inherited by child processes. Pin mode installs no rules and takes no lock.

### Things to know

- `route=default` needs a device the client creates itself, so that the device
  disappears with the process. If the name you give (`tun://wst0?route=default`)
  already exists, for example a persistent device made with `ip tuntap add`, the
  client refuses to start. A persistent device would keep carrying the default
  route after a crash, with nobody reading its packets, and the host would have no
  working route until someone removed it. Delete the device or omit the name. The check is atomic: the device
  is opened with `IFF_TUN_EXCL`, so one created between the check and the open is refused too.
- **Remote administration over the same path.** Only the client's own sockets are
  marked. Replies from any other local socket, such as sshd answering an
  administrator who connects to the host, follow the full tunnel's routing: if the
  administrator's address is reachable only through the default route, the replies
  go into the tunnel and that session is cut, and new ones fail. What keeps a peer
  connected, checked in the namespace tests for both modes: a peer on a directly
  connected network, and a peer behind a more specific route in the main table (for
  example `ip route add 198.51.100.0/24 via <gateway>`, tested by adding it
  while the tunnel runs). In `fwmark` mode the `suppress_prefixlength 0` rule makes
  every main-table route except the default one win; in `pin` mode a route longer
  than `/1` wins by longest prefix over the two `/1` halves. Add such a route for
  your management network before relying on `route=default` on a machine you only
  reach remotely.
- In a full tunnel (fwmark mode) a socket that cannot be marked fails the
  connection attempt with an error naming `SO_MARK`; the client never connects
  unmarked, because the tunnel's own packets would loop into the tunnel. Outside a
  full tunnel `--socket-so-mark` stays best effort.
- `connection_min_idle` cannot be combined with `route=default`: pooled
  connections are opened before the routing exists and would be cut off. The
  client refuses to start.
- The mark is also the routing table id, so `--socket-so-mark` must not be `0`,
  `253`, `254` or `255` with `fwmark` (the client refuses). Any other tunnels the
  same client process runs carry the same mark.
- `pin` needs a route lookup per server address before each connect. It finds the
  route in the main routing table; setups that steer the server's traffic with
  other policy rules are not followed.
- While the server is unreachable, traffic is dropped, not sent out of the
  default route; the namespace tests assert this with a packet sniffer.

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

This is for split-route tunnels. The full tunnel (`route=default`) refuses an
existing device and needs `CAP_NET_ADMIN` to create its own.

With `configure=true` against an existing persistent device, the addresses,
routes and link state the client sets stay after it exits; the client only removes
what it created when the device itself goes away. For a persistent device, prefer
`configure=false` and manage it yourself, as above.

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
them explicitly (loopback, link-local, the cloud metadata addresses, and IPv6
forms that embed them).

To narrow the reachable networks further without writing rules, start the server
with `--tun-allow 10.0.0.0/8` (repeatable; YAML `tun_allow`; Caddyfile
`tun_allow`). A flow must then be inside one of the listed networks and also pass
the rules; the deny list still applies.

Behind Caddy, use the module's `wstunnel` directive with `enable_tun`; see
[CONFIG.md](CONFIG.md#caddy-module). Caddy serves the WebSocket and HTTP/2
transports, not WebTransport.

Server limits, all in [CONFIG.md](CONFIG.md): `tun_max_sessions`, `tun_max_flows`
and `tun_udp_timeout`.

## Deployment

The examples below are also in `packaging/examples` and `packaging/systemd`.
The server does not need `CAP_NET_ADMIN` for tun mode: it terminates packets in
userspace. Only the client creates a device and needs that capability. (Setting
`socket_so_mark` on the server does need it, but that is unrelated to tun.)

`--config` is a global option, so it goes before the subcommand:
`wstunnel-go --config FILE server`, not `wstunnel-go server --config FILE`.

### Server option 1: standalone wstunnel-go under systemd

Save the rules from [Server setup](#server-setup) as
`/etc/wstunnel-go/tun-rules.yaml`, and put the server settings in
`/etc/wstunnel-go/tun-server.yaml`:

```yaml
mode: server
log_lvl: INFO
server:
  listen_addr: "wss://0.0.0.0:443"
  tls_certificate: /etc/wstunnel-go/tls/fullchain.pem
  tls_private_key: /etc/wstunnel-go/tls/privkey.pem
  restrict_config: /etc/wstunnel-go/tun-rules.yaml
  enable_tun: true
  tun_udp_timeout: 30s
  tun_max_flows: 4096
  tun_max_sessions: 256
  tun_allow:
    - 10.0.0.0/8
```

The packaged template unit `wstunnel-go-server@.service` runs
`wstunnel-go --config /etc/wstunnel-go/%i.yaml server` and already grants
`CAP_NET_BIND_SERVICE` for port 443:

```ini
[Service]
ExecStart=/usr/bin/wstunnel-go --config /etc/wstunnel-go/%i.yaml server
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
```

The instance name after `@` selects the file:

```bash
sudo systemctl enable --now wstunnel-go-server@tun-server
```

The same server without a config file:

```bash
wstunnel-go server --enable-tun --restrict-config /etc/wstunnel-go/tun-rules.yaml \
  --tun-allow 10.0.0.0/8 --tun-udp-timeout 30s --tun-max-flows 4096 --tun-max-sessions 256 \
  --tls-certificate /etc/wstunnel-go/tls/fullchain.pem \
  --tls-private-key /etc/wstunnel-go/tls/privkey.pem wss://0.0.0.0:443
```

### Server option 2: the Caddy module

Build Caddy with the module (see the [README](../README.md#caddy-integration-server))
and let Caddy get the certificate and terminate TLS. `wstunnel` handles the
WebSocket and HTTP/2 transports itself:

```caddyfile
tunnel.example.com {
    route /v1/* {
        wstunnel {
            prefix v1
            enable_tun
            restrict_config /etc/wstunnel-go/tun-rules.yaml
            tun_allow 10.0.0.0/8
        }
    }
}
```

The client keeps its default prefix `v1`. The rules file is the one from
[Server setup](#server-setup). Run Caddy as usual, for example with the
`caddy.service` unit from your distribution; no extra capability is needed.

### Server option 3: Caddy in front of a standalone server

Caddy can also forward to a separate wstunnel-go server and keep the certificate,
the public listener and any other sites. Run the standalone server on loopback
without TLS, with the same YAML as option 1 but:

```yaml
mode: server
server:
  listen_addr: "ws://127.0.0.1:8080"
  restrict_config: /etc/wstunnel-go/tun-rules.yaml
  enable_tun: true
  tun_allow:
    - 10.0.0.0/8
```

The server tells the transports apart by the request: an HTTP/2 request without
`Upgrade: websocket` is the HTTP/2 transport, anything else is a WebSocket
upgrade. Caddy must therefore speak HTTP/2 to the server for clients that came in
over HTTP/2 (cleartext h2c; the server accepts it on the same port), and
HTTP/1.1 with the upgrade for WebSocket clients. A single `h2c://` upstream
fails for WebSocket (the client sees `502 Bad Gateway`), and a plain HTTP/1.1
upstream gives the server an HTTP/1.1 request that it does not treat as the HTTP/2
transport, so send each kind to its own upstream:

```caddyfile
tunnel.example.com {
    handle /v1/* {
        @h2 protocol http/2+
        reverse_proxy @h2 h2c://127.0.0.1:8080 {
            flush_interval -1
        }
        reverse_proxy 127.0.0.1:8080
    }
}
```

`flush_interval -1` makes Caddy send data to the client as it arrives instead of
buffering it. Because the server sees only Caddy's connection, a `ClientCommonName`
match in a restriction rule (mTLS) cannot work in this layout; use the module
(option 2) if you need it. Keep the standalone server bound to
loopback: in the default `--mode rust` it does not verify tokens, and the rules
and `tun_allow` are then the only access control.

### Client: one command line

Quote the whole argument, because `&` is special in a shell. Inside the
argument, `/` in `addr` and `route` can be written as `%2F`:

```bash
sudo wstunnel-go client \
  -L 'tun://wst0?addr=198.18.0.1%2F32&route=10.0.0.0%2F8&route=172.16.0.0%2F12&mtu=1400' \
  wss://tunnel.example.com
```

### Client: the same tunnel from a config file

Save this as `/etc/wstunnel-go/tun-client.yaml`. The server URL and the tunnel
are both in the file:

```yaml
mode: client
log_lvl: INFO
client:
  remote_addr: "wss://tunnel.example.com"
  local_to_remote:
    - "tun://wst0?addr=198.18.0.1%2F32&route=10.0.0.0%2F8&route=172.16.0.0%2F12&mtu=1400"
```

Run it with:

```bash
sudo wstunnel-go --config /etc/wstunnel-go/tun-client.yaml client
```

As a service, use `wstunnel-go-tun-client@.service`. It differs from the plain
client unit only in granting `CAP_NET_ADMIN`, which is what creating the device,
its addresses and its routes requires:

```ini
[Service]
ExecStart=/usr/bin/wstunnel-go --config /etc/wstunnel-go/%i.yaml client
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
```

```bash
sudo systemctl enable --now wstunnel-go-tun-client@tun-client
```

### Client: full tunnel from one command line

Every option spelled out; `/` in a prefix is written as `%2F`, and the whole
argument is quoted:

```bash
sudo wstunnel-go client \
  -L 'tun://wst0?addr=198.18.0.1%2F32&addr=fd77:7473::1%2F128&mtu=1400&route=default&routing=auto&dns=1.1.1.1&dns=2606:4700:4700::1111&configure=true' \
  --http-upgrade-path-prefix v1 \
  wss://tunnel.example.com
```

The short form with the defaults is `-L 'tun://wst0?route=default'`, and
`-L 'tun://wst0?route=default&routing=auto&dns=1.1.1.1'` adds a DNS server. The
server needs a rule that admits the destinations, for example `cidr: [0.0.0.0/0,
::/0]` next to the `Tun` entry.

### Client: the same full tunnel from a config file

Save this as `/etc/wstunnel-go/tun-client-full.yaml` (also in
`packaging/examples/tun-client-full.yaml`):

```yaml
mode: client
log_lvl: INFO
client:
  remote_addr: "wss://tunnel.example.com"
  http_upgrade_path_prefix: v1
  local_to_remote:
    - "tun://wst0?addr=198.18.0.1%2F32&addr=fd77:7473::1%2F128&mtu=1400&route=default&routing=auto&dns=1.1.1.1&dns=2606:4700:4700::1111&configure=true"
```

```bash
sudo wstunnel-go --config /etc/wstunnel-go/tun-client-full.yaml client
```

As a service, the same unit as above runs it; only the instance name changes:

```bash
sudo systemctl enable --now wstunnel-go-tun-client@tun-client-full
```

For the routing, the unit grants what the full tunnel needs: the policy rules and
routes are installed over netlink and the firewall mark is set on the client's own
sockets (`SO_MARK`), and the namespace tests run those parts with root in a user
namespace, which shows nothing else is required for them. They do not run under a
restricted capability bounding set, and they do not run `resolvectl` at all. `dns=`
runs `resolvectl`, which asks systemd-resolved over D-Bus; whether that call is
allowed to a service holding only `CAP_NET_ADMIN` depends on the systemd and polkit
versions and policy on the host and has not been verified here. If it is refused,
the client logs a warning and carries on without DNS settings (each `resolvectl`
command gets 10 seconds and is run before the routing is installed, so a stuck
resolver cannot leave the host captured). To get the DNS settings anyway: add a
polkit rule that lets the service's user call `resolvectl` on the link, run the
client as a user systemd-resolved allows, or configure DNS yourself (for example
`resolvectl dns <tun> ...` from the administrator's side) and leave `dns=` out.
`Restart=always` brings the tunnel back after a fatal device error, and
systemd's SIGTERM on stop makes the client remove its rules before it exits.

To run a split-route client (not the full tunnel, which always needs it)
without `CAP_NET_ADMIN`, create a persistent device as in
[Without root](#without-root), use `tun://wst0?configure=false` in the file, and
in a drop-in (`systemctl edit wstunnel-go-tun-client@tun-client`) clear the
capabilities and name a user that owns the device:

```ini
[Service]
User=tunuser
AmbientCapabilities=
CapabilityBoundingSet=
```

## Behaviour and limits

- **TCP and UDP only.** ICMP is not forwarded, so `ping` through the tunnel does
  not work. DNS works when the resolver is inside a routed network (it is UDP).
- **Reconnects.** If the connection to the server drops, the device and its routes
  stay up and the client reconnects, waiting 1 second and doubling up to 30
  seconds between attempts. While it is down, traffic for the routed networks is
  dropped; it does not leak out of your normal route. Connections that were open
  when the session dropped are reset, and new ones work after the reconnect.
- **Dead peers.** Over the websocket transports (`ws://`, `wss://`, and `--mode ws`)
  the client pings every `--websocket-ping-frequency` (30 seconds by default) and
  drops and re-establishes the session if nothing at all arrives from the server
  within three ping intervals, so a connection silently dropped by a NAT or
  firewall is replaced in about 90 seconds instead of hanging. Over HTTP/2
  (`http://`, `https://`) the transport does the same with the same interval: it
  sends an HTTP/2 PING after one interval without any frame and closes the
  connection if the PING is not answered within two more, and the session is then
  re-established. Other HTTP/2 tunnels (`-L tcp://...`) are not changed.
  WebTransport sends QUIC keepalives every 15
  seconds, so an idle session stays up, and it does not need the websocket
  watchdog because QUIC ends a connection that stops answering.
  `--websocket-ping-frequency 0` turns the websocket and HTTP/2 detection off.
- **Exit and signals.** On SIGINT, SIGTERM or SIGHUP (a closed terminal counts as
  a stop request; there is no reload) the client closes the tunnel, removes
  everything it installed (see [Cleanup](#cleanup-and-crash-recovery)) and exits
  0. After the first signal the handlers are released, so a second signal ends the
  process at once the normal way, without cleanup, if the orderly shutdown hangs. If the TUN device fails (for example it is deleted under the client), the
  client logs the error, cleans up and exits non-zero, so a service manager
  restarts it. Programs that embed the client call `StartTun`, which returns a
  handle with `Done`, `Err` and `Close` and never exits the process.
- **Transports.** Works over `ws://`, `wss://`, `http://`, `https://`, `wt://`
  and `wts://`, and with `--mode ws`. The automated tests run tun mode end to end
  over the websocket (both modes), HTTP/2 and WebTransport transports without TLS
  in network namespaces, and over `wss://` and `https://` with a self-signed
  certificate and over an IPv6 server address in process. WebTransport with TLS
  has no tun-specific test.
- **Whole-host routes.** A `/0` route and the two `/1` halves (`0.0.0.0/1` with
  `128.0.0.0/1`, `::/1` with `8000::/1`) given as `route=` values are rejected
  at startup; write `route=default` instead.
- **Performance.** Packets are read and written one at a time, without kernel
  offloads, so very high throughput is not a goal of this version.

## Security

In the default `--mode rust` the server does not verify the signature of the
tunnel token, for compatibility with Rust. Anyone who can reach a server started
with `--enable-tun` can open tun sessions, limited only by the restriction rules.
Treat the rules as the access control: allow only the networks that should be
reachable, use `--mode ws` with a `jwt_secret` where you can, and use TLS (and
mTLS, with a rule that matches `ClientCommonName`) on the listener. A `wss://` or
`https://` listener address does not by itself enable TLS; the server needs
`--tls-certificate` and `--tls-private-key`.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `403 Forbidden (is the server started with --enable-tun, ...)` | The server lacks `--enable-tun`, or no rule allows protocol `Tun` for your path or client certificate. |
| `route ... contains the tunnel server ...` | A `route` covers the server's address. Narrow the route. |
| `route ... would capture all IPv4 traffic` | A `/0` or `/1` route. Use `route=default`. |
| `routing=fwmark cannot work here: strict reverse-path filtering` | Use `routing=pin` or `routing=auto`, or relax `rp_filter`. |
| With `route=default` the session never comes up, `routing=fwmark`, rp_filter unreadable | Strict `rp_filter` may be dropping the server's replies. Use `routing=pin`. |
| `route=default cannot be combined with connection_min_idle` | Remove `connection_min_idle` from the config. |
| `--socket-so-mark N cannot be used for a full tunnel` | `N` is `0`, `253`, `254` or `255`, which are not usable as a routing table id. |
| `tunnel server address never resolved` (repeated, full tunnel) | The name could not be resolved and there is no earlier address to fall back on; use an IP address. |
| Rules at priority 32760 or 32761 after a crash | Harmless; the next start (same fwmark) removes them. To remove them by hand: `ip rule del pref 32760; ip rule del pref 32761` (and `ip -6 ...`). |
| `a policy rule at priority 32760 or 32761 that this client did not install` | Another full tunnel is active, or a stale rule of another fwmark is left. Remove it with `ip rule del pref <n>` (and `ip -6 rule del pref <n>`), then start again. |
| `cannot create or attach tun device ... CAP_NET_ADMIN` | Run as root, or attach to a persistent device with `configure=false`. |
| `tun device ... is already attached by another process` | A persistent device can be used by one process at a time. Stop the other client or use another device. |
| `configure wst0: set mtu ...: operation not permitted` | You asked the client to configure the device without `CAP_NET_ADMIN`. Use `configure=false`. |
| Connections to a routed network are refused | A rule does not allow that destination. The server logs `tun flow denied` with the destination. |
| Connections hang right after the client starts | The session is still being established; they succeed after the first retry. |
