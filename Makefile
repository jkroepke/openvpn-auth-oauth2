##
# Console Colors
##
GREEN  := \033[0;32m
YELLOW := \033[0;33m
WHITE  := \033[0;37m
CYAN   := \033[0;36m
RESET  := \033[0m

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
	@printf "  ${GREEN}make${RESET} ${YELLOW}<target>${RESET}\n"
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
	@go -C tools get -u
	@go -C tools mod tidy
	@go -C pkg/plugin mod tidy
	@go work sync

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
fmt: install-tools
	@-go fmt ./...
	@-tools/bin/gci write .
	@-tools/bin/gofumpt -l -w .
	@-tools/bin/goimports -l -w .
	@-tools/bin/wsl -strict-append -test=true -fix ./...
	@-tools/bin/perfsprint -fix ./...
	@-tools/bin/godot -w .
	@tools/bin/golangci-lint run ./... --fix

.PHONY: golangci
golangci:
	@go run github.com/golangci/golangci-lint/cmd/golangci-lint@${GO_LINT_CI_VERSION} run ./...

.PHONY: 3rdpartylicenses
3rdpartylicenses:
	@go run github.com/google/go-licenses@latest save . --save_path=3rdpartylicenses

# In order to help reduce toil related to managing tooling for the open telemetry collector
# this section of the makefile looks at only requiring command definitions to be defined
# as part of $(TOOLS_MOD_DIR)/tools.go, following the existing practice.
# Modifying the tools' `go.mod` file will trigger a rebuild of the tools to help
# ensure that all contributors are using the most recent version to make builds repeatable everywhere.
TOOLS_MOD_DIR    := tools
TOOLS_MOD_REGEX  := "\s+_\s+\".*\""
TOOLS_PKG_NAMES  := $(shell grep -E $(TOOLS_MOD_REGEX) < $(TOOLS_MOD_DIR)/tools.go | tr -d " _\"")
TOOLS_BIN_DIR    := bin
TOOLS_BIN_NAMES  := $(addprefix $(TOOLS_BIN_DIR)/, $(notdir $(TOOLS_PKG_NAMES)))

.PHONY: install-tools
install-tools: $(TOOLS_BIN_NAMES)

$(TOOLS_BIN_DIR):
	@mkdir -p $@

$(TOOLS_BIN_NAMES): $(TOOLS_BIN_DIR) $(TOOLS_MOD_DIR)/go.mod
	go build -C $(TOOLS_MOD_DIR) -o $@ -trimpath $(filter %/$(notdir $@),$(TOOLS_PKG_NAMES))
