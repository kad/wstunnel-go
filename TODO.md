[x] update README to match current implementation state and interoperability state :
   - **Sections:** Add/update: Features, Installation, Usage, Configuration, API Reference, Contributing, License.
   - **Content:** Detail current features, dependencies, setup steps, operational examples, and interoperability matrix.
   - **Metrics:** Quantify performance benchmarks, compatibility versions.
   - **Clarity:** Ensure precise technical language, consistent formatting.
   - **Consistency:** update AGENTS.md if necessary for new features or specifics
[x]  try to investigage on adding more interoperability e2e test to the project for different tunnel types and command line
   arguments variations.
   - Define test cases for TCP, UDP, and HTTP tunnels. Validate argument permutations: --port, --host,
   --key, --cert. Ensure coverage for TLS/SSL configurations. Measure success via exit codes and log analysis.
[x] add mode to go version that would be RFC 6455 compliant, with a note that only go clients will be able to work in that mode.
   add command line and config option for this mode (keep compatibility wuth rust as a default mode of operation)
   **Implementation Details:**
   - **Protocol:** WebSocket (RFC 6455)
   - **Mode:** `ws`
   - **Client Constraint:** Go-specific clients only
   - **Error Handling:** Strict RFC 6455 adherence
   - **Testing:** Unit tests for compliance
   - **CLI Flag:** `--mode ws` for strict compliance to rfc6455 and propose good
     value for non-compliant (default) mode.
   - **Config Key:** `mode: ws`
   - **Default Mode:** `rust`
   - **Dependencies:** gorilla/websocket can be used, but only in cases if rfc compliant protocol. in non-complaint mode it should be using own
   implementation.
   - **Go Lib:** `gorilla/websocket`
   - **Error Codes:** Map RFC 6455 codes
   - **Handshake:** Validate headers
   - **Framing:** Implement message framing
   - **Subprotocol:** Negotiate if needed
   - **Ping/Pong:** Handle control frames
   - **Close Frame:** Proper close sequence
   - **Test Cases:** Edge cases, invalid frames
[x] Add support for running wstunnel-go via systemd
   - create ssytemd template units for both client and server to use config
     files
   - Update documentation about how to use via config files with systemd units
   - Include systemd units to binary distribution archives
[x] Add distribution packages for goreleaser target rules
[x] Add support (scripts) for starting wstunnel-go client on Windows via task scheduler
   - include install and uninstall scripts
   - include scripts to enable/disable task in task scheduler,
     start/stop/restart
   - add example configs
[x] For client mode, add persistence functionality
   - client should not exit if connection to server got broken, it should try to
     reconnect
[x] Caddy integration (server):
   - consider example implementation of caddy app plugin that can be built into caddy server to allow serving wstunnels.
   - configuration should be able to specify "users" by path prefixes
   - for each user or groups of users it should be possible to define rules which types of tunnels will be allowed
   - for mTLS it should relay on caddy's server socket
