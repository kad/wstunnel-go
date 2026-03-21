# Configuration Guide

`wstunnel-go` supports CLI flags and YAML config files. This guide focuses on the YAML format used by `--config`.

## File structure

Configuration files use a top-level wrapper with `mode`, plus either a `client` or `server` section:

```yaml
mode: client
log_lvl: INFO
no_color: false

client:
  remote_addr: wss://tunnel.example.com
  local_to_remote:
    - "tcp://127.0.0.1:8443:internal.service:443"
```

Top-level fields:

- `mode`: `client` or `server`. Must match the populated section.
- `log_lvl`: `TRACE`, `DEBUG`, `INFO`, `WARN`, `ERROR`, or `OFF`.
- `no_color`: disables colored log output.

Notes:

- Duration values use Go duration syntax such as `10s`, `5m`, or `1h`.
- Tunnel definitions in `local_to_remote` and `remote_to_local` use the same syntax as the CLI `-L` and `-R` flags.
- The config loader maps directly onto the current Go structs. Unknown keys are ignored by YAML parsing, so typos can silently do nothing.

## Client configuration

Example client config with common options:

```yaml
mode: client
log_lvl: INFO
no_color: false

client:
  remote_addr: wss://tunnel.example.com
  http_upgrade_path_prefix: v1
  mode: rust
  jwt_secret: ""

  http_headers:
    X-Env: production
    X-Cluster: edge-a
  http_headers_file: /etc/wstunnel-go/client-headers.txt
  http_upgrade_credentials: "user:password"

  websocket_ping_frequency: 30s
  websocket_mask_frame: false

  tls_verify_certificate: true
  tls_certificate: /etc/wstunnel-go/client.crt
  tls_private_key: /etc/wstunnel-go/client.key
  tls_sni_override: tunnel.example.com
  tls_sni_disable: false
  tls_ech_enable: false

  socket_so_mark: 0
  connection_min_idle: 2
  connection_retry_max_backoff: 5m
  reverse_tunnel_connection_retry_max_backoff: 1m

  http_proxy: http://proxy.example.net:3128
  http_proxy_login: ""
  http_proxy_password: ""

  dns_resolver:
    - dns://1.1.1.1
    - dns://8.8.8.8
  dns_resolver_prefer_ipv4: false

  local_to_remote:
    - "tcp://127.0.0.1:8443:internal.service:443"
    - "udp://127.0.0.1:1053:1.1.1.1:53?timeout_sec=10"
    - "socks5://127.0.0.1:1080?login=admin&password=secret"
    - "http://127.0.0.1:8080?login=proxy&password=secret"
    - "unix:///tmp/wstunnel.sock:/var/run/docker.sock"

  remote_to_local:
    - "tcp://0.0.0.0:2222:127.0.0.1:22"
    - "unix://wstunnel.sock:/var/run/app.sock"
```

### Client options

- `remote_addr`: server URL. Use `ws://` / `wss://` for websocket transport and `http://` / `https://` for HTTP/2.
- `http_upgrade_path_prefix`: path prefix used for websocket upgrade / HTTP tunnel endpoints. Default is usually `v1`.
- `mode`: transport framing mode. Use `rust` for compatibility with the original Rust implementation, or `ws` for strict RFC 6455 websocket mode.
- `jwt_secret`: optional shared secret used to sign client tunnel JWTs. If unset, the client preserves legacy Rust-compatible behavior.
- `http_headers`: map of extra request headers added to the server request.
- `http_headers_file`: file with `Header: value` lines. If set, values from the file override duplicate keys in `http_headers`.
- `http_upgrade_credentials`: basic auth credentials sent in the `Authorization` header.
- `websocket_ping_frequency`: websocket ping interval.
- `websocket_mask_frame`: enable masking on websocket frames.
- `tls_verify_certificate`: verify server certificates when using TLS.
- `tls_certificate`: client certificate path for mTLS.
- `tls_private_key`: private key matching `tls_certificate`.
- `tls_sni_override`: override the SNI hostname sent during TLS handshake.
- `tls_sni_disable`: disable SNI.
- `tls_ech_enable`: enable ECH if supported by the runtime/server path.
- `socket_so_mark`: Linux `SO_MARK` value for outbound connections.
- `connection_min_idle`: keep that many idle client-to-server transport connections open.
- `connection_retry_max_backoff`: max backoff while retrying regular client connections.
- `reverse_tunnel_connection_retry_max_backoff`: max backoff while retrying reverse-tunnel control connections.
- `http_proxy`: upstream HTTP proxy URL used to reach the wstunnel server.
- `http_proxy_login`: optional proxy username override.
- `http_proxy_password`: optional proxy password override.
- `dns_resolver`: explicit resolvers to use.
- `dns_resolver_prefer_ipv4`: prefer IPv4 answers when both families are available.
- `local_to_remote`: list of forward tunnels started locally.
- `remote_to_local`: list of reverse tunnels exposed on the server and forwarded back to the client.

### Client tunnel examples

- `tcp://127.0.0.1:8080:example.com:80`: expose local TCP port `8080`, forward to `example.com:80`.
- `udp://127.0.0.1:5353:1.1.1.1:53?timeout_sec=10`: forward UDP with a 10 second idle timeout.
- `socks5://127.0.0.1:1080`: local SOCKS5 proxy.
- `socks5://127.0.0.1:1080?login=admin&password=secret`: local SOCKS5 proxy requiring credentials.
- `http://127.0.0.1:8080`: local HTTP CONNECT proxy.
- `http://127.0.0.1:8080?login=proxy&password=secret`: local HTTP CONNECT proxy requiring credentials.
- `unix:///tmp/wstunnel.sock:/var/run/docker.sock`: local unix socket listener forwarding to a unix socket target.
- `tcp://0.0.0.0:2222:127.0.0.1:22` under `remote_to_local`: reverse TCP tunnel.

### Current client limitations

- Reverse UDP, reverse SOCKS5, and reverse HTTP proxy are not implemented in this Go version yet. Do not place those tunnel types in `remote_to_local`.

## Server configuration

Example server config with TLS, restrictions, and compatibility options:

```yaml
mode: server
log_lvl: INFO
no_color: false

server:
  listen_addr: wss://0.0.0.0:8443
  http_upgrade_path_prefix: v1
  mode: rust

  jwt_secret: ""
  insecure_no_jwt_validation: false

  websocket_ping_frequency: 30s
  websocket_mask_frame: false

  socket_so_mark: 0
  dns_resolver:
    - dns://1.1.1.1
  dns_resolver_prefer_ipv4: false

  restrict_to:
    - "127.0.0.1:22"
    - "internal.service:443"
  restrict_http_upgrade_path_prefix_list:
    - v1
    - edge
  restrict_config: /etc/wstunnel-go/restrictions.yaml

  tls_certificate: /etc/wstunnel-go/server.crt
  tls_private_key: /etc/wstunnel-go/server.key
  tls_client_ca_certs: /etc/wstunnel-go/clients-ca.pem

  http_proxy: ""
  http_proxy_login: ""
  http_proxy_password: ""

  remote_to_local_server_idle_timeout: 3m
```

### Server options

- `listen_addr`: server bind URL. Examples: `ws://0.0.0.0:8080`, `wss://0.0.0.0:8443`, `http://0.0.0.0:8080`, `https://0.0.0.0:8443`.
- `http_upgrade_path_prefix`: path prefix used for incoming tunnel requests.
- `mode`: websocket compatibility mode. Use `rust` to match Rust framing/behavior or `ws` for RFC 6455 websocket handling.
- `jwt_secret`: optional verification secret for tunnel JWTs.
- `insecure_no_jwt_validation`: skip signature validation for compatibility. In `rust` mode the server stays compatible with Rust-style HS256 token handling.
- `websocket_ping_frequency`: websocket ping interval sent by the server.
- `websocket_mask_frame`: enable websocket frame masking.
- `socket_so_mark`: Linux `SO_MARK` value for outbound connections made by the server.
- `dns_resolver`: explicit resolvers the server should use.
- `dns_resolver_prefer_ipv4`: prefer IPv4 DNS results when both families are present.
- `restrict_to`: allow-list of destinations that clients may request.
- `restrict_http_upgrade_path_prefix_list`: allow-list of accepted path prefixes.
- `restrict_config`: path to restriction rules file.
- `tls_certificate`: PEM certificate used by the server.
- `tls_private_key`: PEM private key matching `tls_certificate`.
- `tls_client_ca_certs`: CA bundle for client-certificate verification (mTLS).
- `http_proxy`: upstream proxy the server should use for outbound requests when relevant.
- `http_proxy_login`: optional proxy username override.
- `http_proxy_password`: optional proxy password override.
- `remote_to_local_server_idle_timeout`: how long an idle reverse listener may stay bound without new client use.

## Restriction config example

The server also supports a separate restrictions file referenced by `restrict_config`. A minimal example looks like this:

```yaml
restrictions:
  - name: allow-ssh
    match:
      - Any
    allow:
      - !Tunnel
        protocol: [tcp]
        host: "^127\\.0\\.0\\.1$"
        port: ["22"]

  - name: allow-edge-prefix
    match:
      - PathPrefix: "^/edge/events$"
    allow:
      - !Tunnel
        protocol: [tcp]
        host: ".*\\.internal\\.example\\.com"
        port: ["443"]

  - name: allow-reverse-tcp
    match:
      - Any
    allow:
      - !ReverseTunnel
        protocol: [reverse_tcp]
        port: ["20000..20100"]
```

`match` entries accept either `Any` or regex-based fields such as `PathPrefix`, `Authorization`, and `ClientCommonName`.

`allow` entries must use tagged YAML objects:

- `!Tunnel` for regular forward tunnels (`tcp`, `udp`, `socks5`, `http_proxy`, `unix`)
- `!ReverseTunnel` for reverse listeners (`reverse_tcp`, `reverse_unix`, and related reverse tunnel protocol names)

Use `restrict_config` when simple `restrict_to` lists are not expressive enough.
