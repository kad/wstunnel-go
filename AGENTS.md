# AGENTS.md - Project Rules and Conventions

This document outlines the established rules, conventions, and processes for the `wstunnel-go` project. It serves as a guide for both human developers and AI agents to ensure consistency, quality, and efficient development.

## 1. Go Version

The project targets **Go version 1.25** or above. This is specified in the `go.mod` file and enforced in the GitHub Workflows.

## 2. Project Structure

The project follows a standard Go project layout:
-   `cmd/wstunnel-go/main.go`: Contains the main application entry point.
-   `pkg/`: Contains internal packages for client, server, protocol, and tunnel logic.
-   `internal/`: Contains internal packages shared between `cmd` and `pkg`.
-   `tests/tester/`: Contains the interoperability testing tool.

## 3. Dependency Management

Dependencies are managed using Go Modules.
-   `go.mod`: Defines the module path, Go version, and direct dependencies.
-   `go.sum`: Contains checksums for direct and indirect dependencies to ensure integrity.

## 4. Makefile Targets

The `Makefile` provides convenient targets for common development tasks:

-   `all`: (Default) Builds the application. Equivalent to `make build`.
-   `build`: Compiles the `wstunnel-go` binary and places it in the `./bin` directory.
-   `test`: Runs all unit and integration tests with verbose output and race detection (`go test -v -race ./...`).
-   `test-interop`: Runs end-to-end interoperability tests between `wstunnel-go` and the original Rust `wstunnel` implementation.
-   `lint`: Executes `golangci-lint` to analyze the codebase for potential issues.
-   `vet`: Runs `go vet` for static analysis.
-   `fmt`: Formats all Go source files using `go fmt`.
-   `tidy`: Organizes Go module dependencies (`go mod tidy`).
-   `verify`: Verifies the integrity of module dependencies (`go mod verify`).
-   `install-tools`: Installs development tools like `golangci-lint` and `goreleaser` locally using `go install`.
-   `clean`: Removes build artifacts, including the `wstunnel-go` binary and any other temporary files.
-   `goreleaser-test`: Tests the `goreleaser` configuration locally without publishing a release (`goreleaser release --snapshot --skip=publish --clean`).
-   `help`: Displays a list of available `Makefile` targets and their descriptions.

## 5. Linting

The project uses `golangci-lint` for static code analysis.
-   **Execution:** Run `make lint` locally. If the tool is not installed, run `make install-tools`.
-   **CI Integration:** `golangci-lint` is automatically run in CI using `golangci/golangci-lint-action@v9` and version `v2.10.1`.

## 6. Testing

### Unit and Integration Tests
-   **Execution:** Tests are run using `go test -v -race ./...`. The `-race` flag enables the data race detector.
-   **CI Integration:** These tests are automatically executed in the CI workflow.

### Interoperability Testing
-   **Purpose:** To validate compatibility with the original Rust `wstunnel` implementation.
-   **Execution:** Run `make test-interop`.
-   **Requirements:** Requires the Rust `wstunnel` binary at `/home/kad/repositories/github.com/kad/wstunnel/target/release/wstunnel`.
-   **Scope:** Tests various client/server combinations (Go-Go, Go-Rust, Rust-Go) across both WebSocket and HTTP/2 transports.

## 7. GitHub Workflows

The project utilizes GitHub Actions for Continuous Integration and Continuous Delivery.

### `ci.yml` (Continuous Integration)
-   **Triggers:** Pushes to `main` and Pull Requests targeting `main`.
-   **Jobs:** `lint`, `test`, `build`.

### `release.yml` (Release Workflow)
-   **Triggers:** Pushes of tags matching `v*`.
-   **Jobs:** `lint`, `test`, `release` (using `goreleaser`).

## 8. Transports

The project supports multiple transport protocols for tunneling:

-   **WebSocket:** (Default) Standard WebSocket-based transport. Uses `Sec-WebSocket-Protocol` header for JWT authentication.
-   **HTTP/2:** Provides full-duplex streaming over HTTP/2 POST requests. Uses `Cookie` header for JWT authentication.

### Client Configuration
Use the `--transport` (or `-t`) flag to specify the transport for the **Go client**:
```bash
wstunnel-go client -t http2 ...
```
The **Rust client** determines the transport based on the server URL scheme (e.g., `ws://` for WebSocket, `http://` for HTTP/2).

### Server Configuration
The server automatically detects the transport and protocol version. No specific configuration is needed to enable HTTP/2 support.

## 9. Goreleaser Configuration

-   **Configuration File:** `.goreleaser.yaml`.
- **Purpose:** Automates cross-platform builds and releases.
- **Local Testing:** Use `make goreleaser-test`.

## 10. Development Cycle

To maintain a high standard of code quality, every completed coding task should include a mandatory verification cycle before it is considered finished. This cycle ensures the codebase is always in good shape and follows established conventions.

1.  **Format:** Run `make fmt` to ensure consistent code styling.
2.  **Build:** Run `make build` to verify that the project compiles successfully.
3.  **Vet:** Run `make vet` to perform static analysis and catch common Go programming errors.
4.  **Lint:** Run `make lint` to ensure the code adheres to all project-specific linting rules.

Following this cycle consistently helps prevent regressions and maintains a professional, high-quality codebase.