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

# Get the GOOS value
GOOS := $(shell go env GOOS)

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
	@rm -rf "$(PROJECT_NAME)" "$(PROJECT_NAME).exe" dist/

.PHONY: check
check: test lint golangci ## Run all checks locally

.PHONY: update
update:  ## Run dependency updates
	@go get -u ./...
	@go mod tidy

.PHONY: build  ## Build the project
build: clean $(PROJECT_NAME)

$(PROJECT_NAME):
	@go build -o $(PROJECT_NAME)$(EXT) .

.PHONY: test
test:  ## Test the project
	@go test -race ./...

.PHONY: lint
lint: golangci  ## Run linter

.PHONY: fmt  ## Format code
fmt:
	@-go fmt ./...
	@-go run github.com/daixiang0/gci@v0.13.7 write .
	@-go run mvdan.cc/gofumpt@v0.9.0 -l -w .
	@-go run golang.org/x/tools/cmd/goimports@v0.36.0 -l -w .
	@-go run github.com/bombsimon/wsl/v5/cmd/wsl@v5.2.0 -fix ./...
	@-go run github.com/catenacyber/perfsprint@v0.9.1 --fix ./...
	@-go run github.com/tetafro/godot/cmd/godot@v1.4.20 -w .
	@-go run github.com/4meepo/tagalign/cmd/tagalign@v1.4.3 -fix -sort ./...
	@-go run golang.org/x/tools/go/analysis/passes/fieldalignment/cmd/fieldalignment@v0.36.0 -test=false -fix ./...
	@-go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.4.0 run ./...

.PHONY: golangci
golangci:
	@go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.4.0 run ./...

.PHONY: 3rdpartylicenses
3rdpartylicenses:
	@go run github.com/google/go-licenses@v1.6.0 save . --save_path=3rdpartylicenses
