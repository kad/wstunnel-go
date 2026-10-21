# Makefile for wstunnel-go

# Variables
GO_VERSION ?= 1.27.2
APP_NAME ?= wstunnel-go
BIN_DIR ?= ./bin
GO_BUILD_LDFLAGS ?= -ldflags="-s -w"
# Keep in sync with .github/workflows/{ci,release}.yml so local lint matches CI.
GOLANGCI_LINT_VERSION ?= v2.14.0

.PHONY: all
all: build ## Build the application (default)

.PHONY: build
build: ## Build the binary
	@echo "Building $(APP_NAME)..."
	@mkdir -p $(BIN_DIR)
	go build $(GO_BUILD_LDFLAGS) -o $(BIN_DIR)/$(APP_NAME) ./cmd/$(APP_NAME)

.PHONY: test
test: ## Run tests
	@echo "Running tests..."
	go test -v -race ./...

.PHONY: test-interop
test-interop: build ## Run interoperability tests with original Rust wstunnel
	@echo "Running interoperability tests..."
	go test -v ./tests/tester/...

.PHONY: lint
lint: ## Run linter (root module)
	@echo "Running golangci-lint..."
	@golangci-lint run ./...

.PHONY: lint-caddy
lint-caddy: ## Run linter on the pkg/caddy module
	@echo "Running golangci-lint (pkg/caddy)..."
	@cd pkg/caddy && golangci-lint run ./...

.PHONY: test-caddy
test-caddy: ## Run tests for the pkg/caddy module
	@echo "Running tests (pkg/caddy)..."
	cd pkg/caddy && go test -race ./...

.PHONY: tidy-caddy
tidy-caddy: ## Tidy the pkg/caddy module
	@echo "Tidying pkg/caddy module..."
	cd pkg/caddy && go mod tidy

.PHONY: check-all
check-all: fmt build vet lint lint-caddy test test-caddy ## Full pre-commit cycle across BOTH modules

.PHONY: install-tools
install-tools: ## Install development tools (golangci-lint, goreleaser)
	@echo "Installing development tools..."
	# The /v2 module path is required: the v1 path resolves to v1.64.8, which is a
	# major-version downgrade from the version CI runs.
	# Installing from source (rather than a prebuilt release) links golangci-lint
	# against the local Go toolchain, so it can always read the standard library's
	# export data. A prebuilt binary built with an older Go fails with
	# "export data version N is greater than maximum supported version M".
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	go install github.com/goreleaser/goreleaser/v2@latest

.PHONY: vet
vet: ## Run go vet
	@echo "Running go vet..."
	go vet ./...

.PHONY: fmt
fmt: ## Run go fmt
	@echo "Running go fmt..."
	go fmt ./...

.PHONY: tidy
tidy: ## Run go mod tidy
	@echo "Tidying go modules..."
	go mod tidy

# The root module and pkg/caddy are separate modules, and pkg/caddy replaces the
# root with the local checkout, so a bump in one must be tidied in the other.
# Only direct requirements are moved to their latest release: the indirect ones
# follow through the module graph. `go get -u` would also push indirect packages
# ahead of what Caddy compiles against (see the cel-go note in dependabot.yml).
# Requirements pinned to a pseudo-version (gvisor) are left alone: the newest
# commit of such a repository may not build, so bump those by hand.
#
# The listing is captured on its own so a failing `go list` stops the target,
# instead of `go get` running with no arguments (which, in pkg/caddy, would
# target the current package and upgrade nothing).
UPGRADE_DIRECT_DEPS = list=$$(go list -m -f '{{if and (not .Main) (not .Indirect) (ne .Path "github.com/kad/wstunnel-go")}}{{.Path}} {{.Version}}{{end}}' all) || exit 1; \
	deps=$$(printf '%s\n' "$$list" | grep -Ev ' v[0-9][^ ]*-[0-9]{14}-[0-9a-f]{12}$$' | awk '{print $$1 "@latest"}'); \
	[ -n "$$deps" ] || { echo "update-deps: no direct dependencies found" >&2; exit 1; }; \
	go get $$deps

.PHONY: update-deps
update-deps: ## Update direct dependencies of BOTH modules to the latest releases, then tidy and build
	@echo "Updating dependencies (root)..."
	@$(UPGRADE_DIRECT_DEPS)
	go mod tidy
	@echo "Updating dependencies (pkg/caddy)..."
	@# The root bump makes pkg/caddy's go.mod stale, and go get refuses to run on it.
	$(MAKE) tidy-caddy
	@cd pkg/caddy && $(UPGRADE_DIRECT_DEPS)
	$(MAKE) tidy-caddy
	go build ./...
	cd pkg/caddy && go build ./...
	@git diff --stat -- go.mod go.sum pkg/caddy/go.mod pkg/caddy/go.sum

.PHONY: verify
verify: ## Run go mod verify
	@echo "Verifying go modules..."
	go mod verify


.PHONY: build-caddy
build-caddy: ## Build Caddy with wstunnel-go module
	@echo "Building Caddy with wstunnel-go module..."
	cd pkg/caddy && xcaddy build --with github.com/kad/wstunnel-go/pkg/caddy=$(CURDIR)/pkg/caddy --with github.com/kad/wstunnel-go=$(CURDIR)

.PHONY: check-caddy
check-caddy: build-caddy ## Check if Caddy module is correctly registered
	./pkg/caddy/caddy list-modules | grep wstunnel

.PHONY: test-caddy-interop
test-caddy-interop: build build-caddy ## Run the tun namespace tests against a real Caddy build
	@echo "Running tun tests against Caddy..."
	WST_CADDY_BIN=$(CURDIR)/pkg/caddy/caddy go test -count=1 -v -run 'TestTunNetns/Go-Caddy' ./tests/tester/

.PHONY: tag
tag: export VERSION := $(VERSION)
tag: ## Prepare matching root and Caddy tags (e.g., make tag VERSION=0.0.4)
	@set -eu; \
	version="$${VERSION#v}"; \
	if ! printf '%s\n' "$$version" | grep -Eq '^(0|1)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$$'; then \
		echo "Error: VERSION must be a stable v0 or v1 release (e.g., 0.0.4 or v0.0.4)" >&2; \
		exit 1; \
	fi; \
	root="v$$version"; \
	caddy="pkg/caddy/v$$version"; \
	if git show-ref --verify --quiet "refs/tags/$$root"; then \
		commit=$$(git rev-parse --verify "refs/tags/$$root^{commit}"); \
	else \
		commit=$$(git rev-parse --verify HEAD); \
	fi; \
	for tag in "$$root" "$$caddy"; do \
		if git show-ref --verify --quiet "refs/tags/$$tag"; then \
			existing=$$(git rev-parse --verify "refs/tags/$$tag^{commit}"); \
			if [ "$$existing" != "$$commit" ]; then \
				echo "Error: $$tag points to a different commit; no tags changed" >&2; \
				exit 1; \
			fi; \
		fi; \
	done; \
	for tag in "$$root" "$$caddy"; do \
		if git show-ref --verify --quiet "refs/tags/$$tag"; then \
			echo "Keeping existing tag $$tag"; \
		else \
			git tag -a "$$tag" "$$commit" -m "Release $$tag"; \
		fi; \
	done; \
	echo "Prepared $$root and $$caddy at $$commit"; \
	echo "To publish: git push --atomic origin refs/tags/$$root refs/tags/$$caddy"

.PHONY: clean
clean: ## Clean build artifacts
	@echo "Cleaning up..."
	go clean
	rm -rf $(BIN_DIR)

.PHONY: goreleaser-test
goreleaser-test: ## Test Goreleaser configuration locally
	@echo "Testing Goreleaser configuration locally..."
	goreleaser release --snapshot --skip=publish --clean

.PHONY: help
help: ## Display this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
