# Makefile for wstunnel-go

# Variables
GO_VERSION ?= 1.25
APP_NAME ?= wstunnel-go
BIN_DIR ?= ./bin
GO_BUILD_LDFLAGS ?= -ldflags="-s -w"

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
lint: ## Run linter
	@echo "Running golangci-lint..."
	@golangci-lint run ./...

.PHONY: install-tools
install-tools: ## Install development tools (golangci-lint, goreleaser)
	@echo "Installing development tools..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
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

.PHONY: tag
tag: ## Create annotated tags for both root and caddy modules (e.g., make tag VERSION=0.0.1)
	@if [ -z "$(VERSION)" ]; then echo "Error: VERSION is required (e.g., make tag VERSION=0.0.1)"; exit 1; fi
	git tag -a v$(VERSION) -m "Release v$(VERSION)"
	git tag -a pkg/caddy/v$(VERSION) -m "Release pkg/caddy v$(VERSION)"
	@echo "Created tags v$(VERSION) and pkg/caddy/v$(VERSION)"

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
