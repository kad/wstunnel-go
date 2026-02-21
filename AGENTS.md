# AGENTS.md - Project Rules and Conventions

This document outlines the established rules, conventions, and processes for the `wstunnel-go` project. It serves as a guide for both human developers and AI agents to ensure consistency, quality, and efficient development.

## 1. Go Version

The project targets **Go version 1.25** or above. This is specified in the `go.mod` file and enforced in the GitHub Workflows.

## 2. Project Structure

The project follows a standard Go project layout:
-   `cmd/wstunnel-go/main.go`: Contains the main application entry point.
-   `pkg/`: Contains internal packages for client, server, protocol, and tunnel logic.

## 3. Dependency Management

Dependencies are managed using Go Modules.
-   `go.mod`: Defines the module path, Go version, and direct dependencies.
-   `go.sum`: Contains checksums for direct and indirect dependencies to ensure integrity.

## 4. Makefile Targets

The `Makefile` provides convenient targets for common development tasks:

-   `all`: (Default) Builds the application. Equivalent to `make build`.
-   `build`: Compiles the `wstunnel-go` binary and places it in the `./bin` directory.
-   `test`: Runs all unit and integration tests with verbose output and race detection (`go test -v -race ./...`).
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
-   **CI Integration:** `golangci-lint` is automatically run in CI using the latest recommended version.

## 6. Testing

All code changes should be accompanied by appropriate tests.
-   **Execution:** Tests are run using `go test -v -race ./...`. The `-race` flag enables the data race detector.
-   **CI Integration:** Tests are automatically executed in the Continuous Integration workflow.

## 7. GitHub Workflows

The project utilizes GitHub Actions for Continuous Integration and Continuous Delivery.

### `ci.yml` (Continuous Integration)

-   **Triggers:** Pushes to the `main` branch and all Pull Requests targeting `main`.
-   **Jobs:**
    -   `lint`: Runs `golangci-lint` using `golangci/golangci-lint-action@v9`.
    -   `test`: Runs `go mod tidy`, `go mod verify`, and `go test -v -race ./...`.
    -   `build`: Builds the application using `make build`.
-   **Go Version:** Uses Go `1.25`.

### `release.yml` (Release Workflow)

-   **Triggers:** Pushes of tags matching `v*` (e.g., `v1.0.0`).
-   **Jobs:**
    -   `lint`: (Dependent on `ci.yml`'s `lint` job) Ensures code quality before release.
    -   `test`: (Dependent on `ci.yml`'s `test` job) Verifies all tests pass before release.
    -   `release`: Uses `goreleaser/goreleaser-action@v6` to build and publish releases to GitHub.
-   **Go Version:** Uses Go `1.25`.

## 8. Goreleaser Configuration

The project uses `goreleaser` for automated releases.
-   **Configuration File:** `.goreleaser.yaml`.
-   **Purpose:** Defines how to build binaries for different platforms (Linux, Windows, macOS) and architectures (amd64, arm64), create archives (`tar.gz`, `zip`), generate checksums, and manage snapshots.
-   **Local Testing:** The `make goreleaser-test` target can be used to test the configuration locally without publishing.
