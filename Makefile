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
