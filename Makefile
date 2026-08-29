##
# Console Colors
##
GREEN  := $(shell printf "\033[0;32m")
YELLOW := $(shell printf "\033[0;33m")
WHITE  := $(shell printf "\033[0;37m")
CYAN   := $(shell printf "\033[0;36m")
RESET  := $(shell printf "\033[0m")

# Get the current working directory
CURRENT_DIR := $(CURDIR)

# Get the directory name of the current working directory
PROJECT_NAME := $(notdir $(CURRENT_DIR))

# Set the local OpenVPN plugin output path
PLUGIN_PATH := $(CURRENT_DIR)/$(PROJECT_NAME).so
PLUGIN_HEADER_PATH := $(CURRENT_DIR)/$(PROJECT_NAME).h

# Get the GOOS value
GOOS := $(shell go env GOOS)

# Get the GOARCH value
GOARCH := $(shell go env GOARCH)

# Build a Linux plugin for the Linux integration test container
ifeq ($(GOOS),linux)
	PLUGIN_BUILD_ENV := CGO_ENABLED=1
else ifeq ($(GOARCH),amd64)
	PLUGIN_BUILD_ENV := GOOS=linux GOARCH=amd64 CGO_ENABLED=1 CC="zig cc -target x86_64-linux-gnu.2.17"
else ifeq ($(GOARCH),arm64)
	PLUGIN_BUILD_ENV := GOOS=linux GOARCH=arm64 CGO_ENABLED=1 CC="zig cc -target aarch64-linux-gnu.2.17"
endif

# Disable CGO for static binaries
CGO_ENABLED := 0

# Determine the output file extension based on the GOOS value
ifeq ($(GOOS),windows)
	EXT := .exe
else
	EXT :=
endif

##
# Targets
##
.PHONY: help
help: ## show this help.
	@echo "Project: $(PROJECT_NAME)"
	@echo 'Usage:'
	@echo "  ${GREEN}make${RESET} ${YELLOW}<target>${RESET}"
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} { \
		if (/^[a-zA-Z_-]+:.*?##.*$$/) {printf "  ${GREEN}%-21s${YELLOW}%s${RESET}\n", $$1, $$2} \
		else if (/^## .*$$/) {printf "  ${CYAN}%s${RESET}\n", substr($$1,4)} \
		}' $(MAKEFILE_LIST) | sort

.PHONY: clean
clean: ## clean builds dir
	@rm -rf "$(PROJECT_NAME)" "$(PROJECT_NAME).exe" "$(PLUGIN_PATH)" "$(PLUGIN_HEADER_PATH)" dist/

.PHONY: check
check: test lint golangci ## Run all checks locally

.PHONY: update
update:  ## Run dependency updates
	@go get -u ./...
	@go mod tidy

.PHONY: renovate
renovate: SHELL := /bin/bash
renovate:  ## Update Renovate test-only Go dependencies
	@set -euo pipefail; \
		production="$$(mktemp)"; \
		tests="$$(mktemp)"; \
		direct="$$(mktemp)"; \
		test_only="$$(mktemp)"; \
		config="$$(mktemp)"; \
		trap 'rm -f "$$production" "$$tests" "$$direct" "$$test_only" "$$config"' EXIT; \
		go list -deps -f '{{with .Module}}{{.Path}}{{end}}' ./... | sort -u > "$$production"; \
		go list -deps -test -f '{{with .Module}}{{.Path}}{{end}}' ./... | sort -u > "$$tests"; \
		go list -m -f '{{if not .Indirect}}{{.Path}}{{end}}' all | sort -u > "$$direct"; \
		comm -13 "$$production" "$$tests" > "$$test_only"; \
		test_dependencies="$$(comm -12 "$$test_only" "$$direct")"; \
		jq --arg dependencies "$$test_dependencies" \
			'(.packageRules[] | select(.groupName == "Go test dependencies").matchPackageNames) = \
			($$dependencies | split("\n") | map(select(length > 0)))' \
			renovate.json > "$$config"; \
		cp "$$config" renovate.json

.PHONY: build  ## Build the project
build: clean $(PROJECT_NAME)

$(PROJECT_NAME):
	@go build -tags no_otel -o $(PROJECT_NAME)$(EXT) ./cmd/openvpn-auth-oauth2

.PHONY: test
test:  ## Test the project
	@GOEXPERIMENT=cgocheck2 go test -race ./...

.PHONY: test-it
test-it:  ## Run integration tests
	@$(PLUGIN_BUILD_ENV) go build -buildvcs=false -buildmode=c-shared -o "$(PLUGIN_PATH)" ./lib/openvpn-auth-oauth2
	@GOEXPERIMENT=cgocheck2 OPENVPN_IT_TEST=1 PLUGIN_IT_TEST=1 PLUGIN_IT_PLUGIN_PATH="$(PLUGIN_PATH)" \
		go test -race -count=1 -timeout=15m -run '^TestIT(EnforceUniqueUser)?$$' ./internal ./lib/openvpn-auth-oauth2

.PHONY: lint
lint: golangci  ## Run linter

.PHONY: textlint
textlint:  ## Run textlint
	npx textlint --rule terminology .

.PHONY: fmt  ## Format code
fmt:
	@go mod tidy
	# ignoring exit codes from linter, because they exited non zero, if they format code.
	@-go fmt ./...
	@-go run github.com/daixiang0/gci@v0.14.0 write .
	@-go run mvdan.cc/gofumpt@v0.11.0 -l -w .
	@-go run golang.org/x/tools/cmd/goimports@v0.49.0 -l -w .
	@-go run github.com/bombsimon/wsl/v5/cmd/wsl@v5.9.0 -fix ./...
	@-go run github.com/catenacyber/perfsprint@v0.10.1 --fix ./...
	@-go run github.com/tetafro/godot/cmd/godot@v1.4.20 -w .
	@-go run github.com/4meepo/tagalign/cmd/tagalign@v1.4.3 -fix -sort ./...
	@-go run github.com/t34-dev/go-field-alignment/v2/cmd/gofield@v2.0.10 --files . -fix
	@-go run golang.org/x/tools/go/analysis/passes/fieldalignment/cmd/fieldalignment@v0.49.0 -test=false -fix ./...
	@-go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.2 run ./...

.PHONY: golangci
golangci:
	@go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.2 run ./...

.PHONY: 3rdpartylicenses
3rdpartylicenses:
	@go run github.com/google/go-licenses/v2@v2.0.1 save ./cmd/openvpn-auth-oauth2 --save_path=3rdpartylicenses
