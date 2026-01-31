# Architecture Review

This document provides a comprehensive architectural review of the openvpn-auth-oauth2 codebase, including design patterns, code organization, and recommendations for improvement.

## Table of Contents

1. [Overview](#overview)
2. [Architecture Patterns](#architecture-patterns)
3. [Package Structure](#package-structure)
4. [Code Quality Assessment](#code-quality-assessment)
5. [Recommendations](#recommendations)

## Overview

`openvpn-auth-oauth2` is a Go application that bridges OpenVPN's management interface with OAuth2/OIDC providers. The codebase follows modern Go practices with a clean package structure and interface-driven design.

**Key Statistics:**
- Total Lines of Code: ~9,300 (internal packages)
- Number of Packages: 22 (including sub-packages)
- Go Version: 1.25
- Main Dependencies: zitadel/oidc, golang.org/x/oauth2

## Architecture Patterns

### 1. Layered Architecture ✅

The codebase follows a clean layered architecture with unidirectional dependencies:

```
┌─────────────────────────────────────┐
│  Presentation Layer                 │
│  - httphandler                      │
│  - httpserver                       │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│  Domain/Business Logic Layer        │
│  - oauth2 (with providers)          │
│  - openvpn                          │
│  - state                            │
│  - tokenstorage                     │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│  Infrastructure Layer               │
│  - config                           │
│  - utils                            │
│  - ui (assets)                      │
└─────────────────────────────────────┘
```

**Strengths:**
- No circular dependencies detected
- Clear separation between layers
- Dependencies flow inward (presentation → domain → infrastructure)

### 2. Interface-Driven Design ✅

The codebase uses interfaces effectively for abstraction and testability:

**OAuth2 Provider Interface** (`internal/oauth2/provider.go`):
```go
type Provider interface {
    CheckUser(ctx, session, user, tokens) error
    GetProviderConfig() (ProviderConfig, error)
    GetName() string
    GetRefreshToken(tokens) (string, error)
    GetUser(ctx, logger, tokens, userinfo) error
}
```

**Implementations:**
- `generic.Provider` - Generic OAuth2/OIDC provider
- `github.Provider` - GitHub-specific implementation
- `google.Provider` - Google-specific implementation

**Benefits:**
- Easy to add new OAuth2 providers
- Mockable for testing
- Clear contracts between components

**OpenVPN Management Client Interface** (`internal/oauth2/handler.go`):
```go
type openvpnManagementClient interface {
    AcceptClient(ctx, logger, client, reAuth, username, clientConfigName)
    DenyClient(ctx, logger, client, reason)
}
```

**Benefits:**
- Decouples OAuth2 handler from OpenVPN implementation
- Enables unit testing without actual OpenVPN connection

### 3. Strategy Pattern ✅

The OAuth2 provider system implements the Strategy pattern, allowing runtime selection of authentication strategies:

```go
// Provider selection in cmd/openvpn-auth-oauth2/root.go
var provider oauth2.Provider
switch conf.OAuth2.Provider {
case "generic":
    provider = generic.New(conf, logger)
case "github":
    provider = github.New(conf, logger)
case "google":
    provider = google.New(conf, logger)
}
```

### 4. Repository Pattern (Partial) ✅

Token storage uses a repository-like pattern:

**Interface** (`internal/tokenstorage/types.go`):
```go
type Storage interface {
    Store(ctx, key, value) error
    Get(ctx, key) (string, error)
    Delete(ctx, key) error
}
```

**Current Implementation:**
- `InMemoryStorage` - Only implementation provided

**Potential Enhancements:**
- Could add Redis, database, or file-based implementations
- Interface is well-designed for extension

## Package Structure

### Core Packages

#### 1. `internal/config` - Configuration Management

**Files:** 10 files, ~1,500 lines total
- `config.go` - Main configuration loader (235 lines)
- `types.go` - Configuration structure definitions (329 lines)
- `types/*.go` - Custom types (URL, Secret, FS, Template, etc.)
- `flags.go` - Command-line flag definitions (437+ flags)
- `validate.go` - Configuration validation (150 lines)
- `defaults.go` - Default values

**Responsibilities:**
- Load configuration from YAML files
- Parse command-line flags
- Read environment variables
- Type-safe configuration with custom unmarshaling
- Configuration validation

**Design Pattern:** Builder pattern for configuration construction

**Configuration Loading Order:**
1. Default values
2. YAML configuration file (if specified)
3. Environment variables (override YAML)
4. Command-line flags (override env vars)

**Strengths:**
- Comprehensive configuration options
- Type-safe with custom types (Secret, URL, etc.)
- Multiple configuration sources with clear precedence
- Good validation logic

**Concerns:**
- Large, deeply nested configuration struct (100+ fields)
- `types.go` is 329 lines with complex nesting
- `flags.go` is very large with repetitive flag definitions

#### 2. `internal/oauth2` - OAuth2/OIDC Client

**Files:** 12 files, ~2,500 lines total
- `handler.go` - HTTP handlers for OAuth2 flow (525 lines) ⚠️
- `provider.go` - Provider interface and factory (198 lines)
- `refresh.go` - Token refresh logic (150 lines)
- `providers/` - Provider implementations (generic, github, google)

**Responsibilities:**
- Handle OAuth2 authorization code flow
- Manage OIDC discovery and token validation
- Provider-specific customizations
- Token refresh with stored refresh tokens
- User validation against claims

**Design Patterns:**
- Strategy pattern (providers)
- Factory pattern (provider creation)
- Dependency injection (logger, config, storage)

**Strengths:**
- Well-abstracted provider interface
- Supports OIDC discovery and manual configuration
- Comprehensive token validation
- Refresh token support

**Concerns:**
- `handler.go` is large (525 lines) with multiple responsibilities
- Could benefit from splitting into smaller, focused handlers

#### 3. `internal/openvpn` - OpenVPN Management Interface

**Files:** 11 files, ~2,000 lines total
- `main.go` - Protocol handler and event loop (337 lines)
- `client.go` - Client authentication logic (207 lines)
- `handler.go` - Command/response handling
- `connection/` - Connection management sub-package

**Responsibilities:**
- Connect to OpenVPN management interface (TCP or Unix socket)
- Parse OpenVPN management protocol messages
- Handle client connect/reauth/disconnect events
- Send accept/deny commands to OpenVPN
- Manage authentication state

**Design Patterns:**
- Command pattern (for OpenVPN commands)
- Event-driven architecture

**Strengths:**
- Clean separation of connection and protocol logic
- Proper timeout handling
- Event-driven design
- Good error handling

**Concerns:**
- `main.go` handles both protocol parsing and orchestration (337 lines)
- Protocol parsing could be extracted to dedicated parser

#### 4. `internal/state` - Session State Management

**Files:** 4 files, ~500 lines total
- `state.go` - State generation and validation (262 lines)
- `encrypt.go` - AES encryption for state (78 lines)

**Responsibilities:**
- Generate encrypted OAuth2 state parameter
- Embed client information (IP, port, CID, KID, session ID)
- Encrypt/decrypt state using AES-GCM
- Protect against CSRF attacks

**Design Pattern:** Value object with encryption

**Strengths:**
- Secure state handling with encryption
- Proper CSRF protection
- Well-tested (state_test.go, bench_test.go)

#### 5. `internal/tokenstorage` - Token Storage

**Files:** 4 files, ~200 lines total
- `types.go` - Storage interface
- `inmemory.go` - In-memory implementation (123 lines)
- `errors.go` - Error definitions

**Responsibilities:**
- Store refresh tokens for silent re-authentication
- Provide abstraction for different storage backends

**Design Pattern:** Repository pattern

**Strengths:**
- Clean interface design
- Easy to extend with new storage backends
- Proper error handling

**Potential Enhancements:**
- Could add persistent storage implementations (Redis, database)
- Could add expiration/TTL support

#### 6. `internal/httphandler` - HTTP Route Handler

**Files:** 2 files, ~100 lines total
- `handler.go` - Route mounting (59 lines)

**Responsibilities:**
- Mount OAuth2 routes
- Serve static assets
- Register health check endpoints

**Strengths:**
- Simple, focused responsibility
- Easy to understand

#### 7. `internal/httpserver` - HTTP Server

**Files:** 2 files, ~250 lines total
- `main.go` - Server setup and lifecycle (203 lines)

**Responsibilities:**
- Configure HTTP/HTTPS server
- TLS certificate loading
- Graceful shutdown
- Proxy header support

**Strengths:**
- Proper graceful shutdown
- TLS support with dynamic certificate loading
- Good error handling

#### 8. `internal/utils` - Utilities

**Files:** 20+ files, ~1,000 lines total
- Common name transformation
- HTTP utilities
- Slice utilities
- String utilities
- Filesystem utilities
- Test utilities (testutils/)

**Responsibilities:**
- Shared utility functions
- Test helpers and mocks

**Strengths:**
- Well-organized test utilities
- Reusable functions

## Code Quality Assessment

### Strengths ✅

1. **No Circular Dependencies**
   - Clean dependency graph with unidirectional flow
   - Packages are properly layered

2. **Interface-Driven Design**
   - OAuth2 providers use interfaces for extensibility
   - Storage uses repository pattern
   - Easy to mock for testing

3. **Comprehensive Testing**
   - Most packages have >80% test coverage
   - Unit tests co-located with source
   - Integration tests in cmd/
   - Test utilities provided (testutils/)
   - Benchmarks included

4. **Consistent Error Handling**
   - Each package defines sentinel errors in errors.go
   - Proper error wrapping with %w
   - Error type checking with errors.Is

5. **Type Safety**
   - Custom types for configuration (Secret, URL, FS, etc.)
   - Type-safe unmarshaling
   - Validation at configuration load time

6. **Documentation**
   - DEVELOPER.md explains architecture
   - docs/ directory with detailed guides
   - Code comments on public APIs

### Areas for Improvement ⚠️

#### 1. Large Handler Files (God Objects)

**Issue:** Some handlers have grown too large with multiple responsibilities.

**Examples:**

a) **`internal/oauth2/handler.go` (525 lines, 14 methods)**
   - Handles OAuth2 flow orchestration
   - Error handling and logging
   - Token management
   - Session creation
   - Profile submission
   
   **Current Methods:**
   - OAuth2Start (95 lines)
   - OAuth2Callback (160 lines)
   - OAuth2ProfileSubmit
   - getClientID
   - createSessionLogger
   - postCodeExchangeHandler
   - storeProfileSelectorToken
   - httpErrorHandler

   **Recommendation:** Split into focused handlers:
   ```
   - AuthorizationHandler (OAuth2Start)
   - CallbackHandler (OAuth2Callback, postCodeExchangeHandler)
   - ProfileHandler (OAuth2ProfileSubmit, storeProfileSelectorToken)
   - ErrorHandler (httpErrorHandler)
   ```

b) **`internal/openvpn/main.go` (337 lines)**
   - Protocol parsing
   - Event loop
   - Command handling
   - State management

   **Recommendation:** Extract protocol parser:
   ```
   - parser.go (protocol message parsing)
   - eventloop.go (main event loop)
   - commands.go (command builders)
   ```

#### 2. Complex Configuration Structure

**Issue:** The Config struct has deep nesting with 100+ fields across multiple levels.

**Current Structure:**
```go
type Config struct {
    HTTP struct {
        BaseURL, Listen, Secret, TLS, Check...
    }
    OAuth2 struct {
        Issuer, Client, Scopes, Validate, Refresh...
        Client struct {
            ID, Secret
        }
        Endpoints struct {
            Authorization, Token, Introspection, Revocation...
        }
        Validate struct {
            IPAddr, CommonName, Issuer, Roles, Groups...
        }
    }
    OpenVPN struct {
        Addr, Password, Bypass, CommonName, Passthrough...
    }
}
```

**Recommendations:**
1. Use Config Builder pattern for construction
2. Group related settings into smaller structs
3. Consider functional options pattern for optional settings

**Example Builder Pattern:**
```go
type ConfigBuilder struct {
    config Config
}

func NewConfigBuilder() *ConfigBuilder {
    return &ConfigBuilder{config: DefaultConfig()}
}

func (b *ConfigBuilder) WithHTTP(http HTTP) *ConfigBuilder {
    b.config.HTTP = http
    return b
}

func (b *ConfigBuilder) Build() (Config, error) {
    return b.config, validate(b.config)
}
```

#### 3. Repetitive Flag Definitions

**Issue:** `flags.go` has 437+ lines of repetitive flag definitions.

**Current Pattern:**
```go
fs.StringVar(&conf.HTTP.Listen, "http.listen", conf.HTTP.Listen, "...")
fs.BoolVar(&conf.HTTP.TLS, "http.tls", conf.HTTP.TLS, "...")
fs.StringVar(&conf.OAuth2.Issuer, "oauth2.issuer", conf.OAuth2.Issuer, "...")
```

**Recommendation:** Use reflection-based flag registration or code generation:
```go
// Using struct tags for flag definition
type Config struct {
    HTTP struct {
        Listen string `flag:"http.listen" default:":8080" usage:"HTTP listen address"`
        TLS    bool   `flag:"http.tls" default:"false" usage:"Enable TLS"`
    }
}

// Auto-register flags from struct tags
registerFlags(fs, &conf)
```

#### 4. Limited Storage Implementations

**Issue:** Only in-memory token storage is implemented. For production use, persistent storage is needed.

**Recommendation:** Add storage implementations:
- Redis storage (for clustered deployments)
- File-based storage (for simple deployments)
- Database storage (PostgreSQL, MySQL)

**Example Interface Usage:**
```go
// Factory function for storage selection
func NewStorage(conf config.Config) tokenstorage.Storage {
    switch conf.Storage.Type {
    case "memory":
        return tokenstorage.NewInMemory()
    case "redis":
        return tokenstorage.NewRedis(conf.Storage.Redis)
    case "file":
        return tokenstorage.NewFile(conf.Storage.FilePath)
    }
}
```

#### 5. Testing Gaps

**Current State:**
- Good unit test coverage
- Integration tests in cmd/
- Test utilities provided

**Gaps:**
- No end-to-end tests with real OAuth2 provider
- No performance/load tests
- No security tests (fuzzing, injection tests)

**Recommendations:**
1. Add E2E tests using testcontainers with mock OIDC provider
2. Add load tests for high-traffic scenarios
3. Add fuzzing tests for protocol parsing
4. Add security tests for injection vulnerabilities

## Recommendations

### High Priority

#### 1. Refactor Large Handlers

**Goal:** Improve maintainability by splitting large handlers into focused components.

**Actions:**
- [ ] Split `oauth2/handler.go` into multiple handler files
  - [ ] Create `authorization_handler.go` for OAuth2Start
  - [ ] Create `callback_handler.go` for OAuth2Callback
  - [ ] Create `profile_handler.go` for profile submission
  - [ ] Create `error_handler.go` for error handling
- [ ] Extract protocol parsing from `openvpn/main.go`
  - [ ] Create `openvpn/parser.go` for message parsing
  - [ ] Keep event loop in `main.go`

**Benefits:**
- Easier to understand and maintain
- Better testability (focused unit tests)
- Clearer responsibilities
- Easier for new contributors

#### 2. Improve Configuration Management

**Goal:** Simplify configuration structure and reduce complexity.

**Actions:**
- [ ] Add ConfigBuilder pattern for optional configuration
- [ ] Group related settings into sub-structs
- [ ] Consider using functional options for complex initialization
- [ ] Document configuration structure in architecture docs

**Example:**
```go
// Functional options pattern
func NewConfig(opts ...ConfigOption) Config {
    conf := DefaultConfig()
    for _, opt := range opts {
        opt(&conf)
    }
    return conf
}

type ConfigOption func(*Config)

func WithOAuth2Provider(provider string) ConfigOption {
    return func(c *Config) {
        c.OAuth2.Provider = provider
    }
}
```

#### 3. Add Architectural Documentation

**Goal:** Make architecture explicit and accessible to contributors.

**Actions:**
- [x] Create this ARCHITECTURE.md document
- [ ] Add sequence diagrams for main flows
- [ ] Document design patterns used
- [ ] Add decision records (ADRs) for key decisions

#### 4. Add Persistent Token Storage

**Goal:** Support production deployments with persistent storage.

**Actions:**
- [ ] Implement Redis storage backend
- [ ] Implement file-based storage backend
- [ ] Add storage configuration options
- [ ] Add storage migration/upgrade support

### Medium Priority

#### 5. Enhance Testing

**Goal:** Increase test coverage and add E2E tests.

**Actions:**
- [ ] Add E2E tests with mock OIDC provider (using testcontainers)
- [ ] Add load/performance tests
- [ ] Add fuzzing tests for protocol parsing
- [ ] Add security tests for common vulnerabilities

#### 6. Extract Protocol Parser

**Goal:** Separate protocol parsing from business logic.

**Actions:**
- [ ] Create dedicated protocol parser package
- [ ] Define protocol message types
- [ ] Add comprehensive protocol tests
- [ ] Document OpenVPN management protocol

#### 7. Improve Error Messages

**Goal:** Make errors more actionable for users.

**Actions:**
- [ ] Add structured error types with error codes
- [ ] Include suggestions in error messages
- [ ] Add error documentation
- [ ] Improve logging context

### Low Priority

#### 8. Code Generation for Flags

**Goal:** Reduce repetition in flag definitions.

**Actions:**
- [ ] Use struct tags for flag metadata
- [ ] Generate flag registration code
- [ ] Add validation in struct tags

#### 9. Performance Optimization

**Goal:** Optimize hot paths and reduce allocations.

**Actions:**
- [ ] Profile authentication flow
- [ ] Optimize state encryption/decryption
- [ ] Pool frequently allocated objects
- [ ] Add benchmarks for critical paths

#### 10. API Documentation

**Goal:** Generate API documentation from code.

**Actions:**
- [ ] Add godoc comments to all exported types/functions
- [ ] Generate API documentation
- [ ] Publish documentation to GitHub Pages

## Conclusion

The openvpn-auth-oauth2 codebase demonstrates solid architectural principles with clean layering, interface-driven design, and comprehensive testing. The main areas for improvement are:

1. **Refactoring large handlers** to improve maintainability
2. **Simplifying configuration** structure
3. **Adding persistent storage** implementations
4. **Enhancing testing** with E2E and security tests

These improvements will make the codebase more maintainable, scalable, and production-ready while preserving its strong architectural foundation.

### Score Summary

| Aspect | Current Grade | Target Grade |
|--------|---------------|--------------|
| Dependency Management | A | A |
| Separation of Concerns | A- | A |
| Error Handling | A | A |
| Configuration | B+ | A |
| Testing | A | A+ |
| Code Organization | B | A |
| Documentation | B+ | A |

**Overall Architecture Grade: A-**

The codebase is well-architected with minor areas for improvement. The recommendations focus on refinement rather than major restructuring, indicating a solid architectural foundation.
