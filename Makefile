##
# Console Colors
##
GREEN  := $(shell tput -Txterm setaf 2)
YELLOW := $(shell tput -Txterm setaf 3)
WHITE  := $(shell tput -Txterm setaf 7)
CYAN   := $(shell tput -Txterm setaf 6)
RESET  := $(shell tput -Txterm sgr0)

##
# Targets
##
.PHONY: help
help: ## show this help.
	@echo 'Usage:'
	@echo '  ${GREEN}make${RESET} ${YELLOW}<target>${RESET}'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} { \
		if (/^[a-zA-Z_-]+:.*?##.*$$/) {printf "  ${GREEN}%-21s${YELLOW}%s${RESET}\n", $$1, $$2} \
		else if (/^## .*$$/) {printf "  ${CYAN}%s${RESET}\n", substr($$1,4)} \
		}' $(MAKEFILE_LIST) | sort

.PHONY: clean
clean: ## clean builds dir
	@rm -rf openvpn-auth-oauth2 dist/

.PHONY: check
check: test lint golangci ## Run all checks locally

.PHONY: build
build: openvpn-auth-oauth2  ## Build openvpn-auth-oauth2

openvpn-auth-oauth2:
	@go build -o openvpn-auth-oauth2 .

.PHONY: test
test:  ## Test openvpn-auth-oauth2
	@go test -race ./...

.PHONY: lint
lint: golangci  ## Run linter

.PHONY: format
format: fmt goimports gofumpt golangci-fix ## Format source code

.PHONY: fmt
fmt:
	@go fmt ./...

.PHONY: gofumpt
gofumpt:
	@go run mvdan.cc/gofumpt@latest -l -w .

.PHONY: goimports
goimports:
	@go run golang.org/x/tools/cmd/goimports@latest -l -w .

.PHONY: golangci
golangci:
	@go run github.com/golangci/golangci-lint/cmd/golangci-lint@v1.55.1 run .

.PHONY: golangci-fix
golangci-fix:
	@go run github.com/golangci/golangci-lint/cmd/golangci-lint@v1.55.1 run . --fix
