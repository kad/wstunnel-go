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
