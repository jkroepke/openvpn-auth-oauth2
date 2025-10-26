 # OpenVPN Plugin Shim - Developer Knowledge Base

This document contains comprehensive technical knowledge about the OpenVPN plugin shim implementation for openvpn-auth-oauth2.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [OpenVPN Plugin API](#openvpn-plugin-api)
3. [Authentication Flow](#authentication-flow)
4. [Deferred Authentication](#deferred-authentication)
5. [Management Interface Protocol](#management-interface-protocol)
6. [File Structure](#file-structure)
7. [Critical Implementation Details](#critical-implementation-details)
8. [Known Limitations](#known-limitations)
9. [Troubleshooting Guide](#troubleshooting-guide)
10. [Future Improvements](#future-improvements)

---

## Architecture Overview

### The Problem

Originally, openvpn-auth-oauth2 connects directly to OpenVPN's management interface. This creates a problem:
- OpenVPN's management interface can only handle ONE client connection at a time
- When openvpn-auth-oauth2 is connected, other management tools cannot connect
- This blocks legitimate uses like server monitoring, dynamic IP management, etc.

### The Solution

The plugin shim acts as a **bridge** between OpenVPN and openvpn-auth-oauth2:

```
┌─────────────────────┐
│   OpenVPN Server    │
│                     │
│  Plugin API calls   │
│  (native C calls)   │
└──────────┬──────────┘
           │
           │ openvpn_plugin_func_v3()
           │ AUTH_USER_PASS_VERIFY
           │
┌──────────▼──────────────────────┐
│  openvpn-auth-oauth2.so         │  <-- This Plugin (Go + CGo)
│                                 │
│  - Receives auth events         │
│  - Opens management socket      │
│  - Translates to mgmt protocol  │
└──────────┬──────────────────────┘
           │
           │ TCP/Unix Socket
           │ Management Interface Protocol
           │
┌──────────▼──────────────────────┐
│  openvpn-auth-oauth2 (binary)   │
│                                 │
│  - Connects to plugin socket    │
│  - Processes OAuth2 auth        │
│  - Sends back auth decisions    │
└─────────────────────────────────┘
```

### Key Benefits

1. **Non-blocking**: OpenVPN's real management interface remains free
2. **Isolation**: Auth logic is separated from OpenVPN internals
3. **Compatibility**: openvpn-auth-oauth2 code remains mostly unchanged
4. **Native Integration**: Uses OpenVPN's official plugin API

---

## OpenVPN Plugin API

### Plugin Lifecycle Functions

The OpenVPN plugin API requires specific exported C functions:

#### 1. `openvpn_plugin_min_version_required_v1()`
Returns the minimum plugin API version (we require v3).

#### 2. `openvpn_plugin_select_initialization_point_v1()`
Tells OpenVPN when to initialize the plugin:
- `OPENVPN_PLUGIN_INIT_PRE_CONFIG_PARSE` - Before config parsing
- `OPENVPN_PLUGIN_INIT_POST_CONFIG_PARSE` - After config parsing
- `OPENVPN_PLUGIN_INIT_PRE_DAEMON` - Before daemonization (default)
- **`OPENVPN_PLUGIN_INIT_POST_UID_CHANGE`** - After dropping privileges (we use this)
- `OPENVPN_PLUGIN_INIT_POST_DAEMON` - After daemonization

We use `POST_UID_CHANGE` because we need to create sockets after OpenVPN has dropped privileges.

#### 3. `openvpn_plugin_open_v3()`
Called when OpenVPN loads the plugin. Our implementation:
- Parses plugin arguments (socket address, optional password)
- Creates management server socket
- Starts listening for openvpn-auth-oauth2 connection
- Returns plugin handle (pointer to our context struct)

**Arguments from OpenVPN config:**
```
plugin /path/to/plugin.so "arg1" "arg2" "arg3"
                           ^      ^      ^
                           |      |      |
                           |      |      +-- argv[3]
                           |      +--------- argv[2] (password)
                           +---------------- argv[1] (socket address)
```

#### 4. `openvpn_plugin_func_v3()`
Called for each plugin event. We handle:
- `OPENVPN_PLUGIN_UP` - Server is ready
- **`OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY`** - Main authentication event
- `OPENVPN_PLUGIN_CLIENT_CONNECT_V2` - Client connecting (post-auth config)
- `OPENVPN_PLUGIN_CLIENT_CONNECT_DEFER_V2` - Polling for deferred auth completion

#### 5. `openvpn_plugin_close_v1()`
Called when plugin is unloaded (server shutdown).

#### 6. `openvpn_plugin_abort_v1()`
Called on emergency shutdown.

### Plugin Event Types

Events are set via `type_mask` bitmask in `openvpn_plugin_open_v3()`:

```go
ret.type_mask = 1<<C.OPENVPN_PLUGIN_UP |
    1<<C.OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY |
    1<<C.OPENVPN_PLUGIN_CLIENT_CONNECT_V2 |
    1<<C.OPENVPN_PLUGIN_CLIENT_CONNECT_DEFER_V2
```

### Return Values

Plugin functions return integer status codes:

- `OPENVPN_PLUGIN_FUNC_SUCCESS` (0) - Operation succeeded
- `OPENVPN_PLUGIN_FUNC_ERROR` (1) - Operation failed
- `OPENVPN_PLUGIN_FUNC_DEFERRED` (2) - Operation is pending (async)

---

## Authentication Flow

### Synchronous Authentication

```
1. Client connects to OpenVPN
   └─> OpenVPN calls plugin: OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY

2. Plugin receives environment variables (username, password, etc.)
   └─> Creates Client object from environment
   └─> Sends to management interface: ">CLIENT:CONNECT,<id>\r\n>CLIENT:ENV,..."

3. openvpn-auth-oauth2 receives client info
   └─> Validates credentials
   └─> Sends response: "client-auth-nt <cid> <kid>" (accept)
                    or "client-deny <cid> <kid> "reason"" (deny)

4. Plugin receives response
   └─> Writes "1" to auth_control_file (accept)
   └─> or writes "0\nreason" to auth_control_file (deny)
   └─> Returns OPENVPN_PLUGIN_FUNC_SUCCESS or ERROR

5. OpenVPN reads auth_control_file
   └─> Accepts or rejects client connection
```

### Asynchronous (Deferred) Authentication for SSO

```
1. Client connects to OpenVPN
   └─> OpenVPN calls plugin: OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY

2. Plugin sends client info to openvpn-auth-oauth2

3. openvpn-auth-oauth2 determines SSO is needed
   └─> Sends: "client-pending-auth <cid> <kid> "WEB_AUTH::<url>" <timeout>"

4. Plugin receives pending auth response
   └─> Writes "2" to auth_control_file (deferred)
   └─> Writes SSO URL to auth_pending_file
   └─> Returns OPENVPN_PLUGIN_FUNC_DEFERRED

5. OpenVPN shows SSO URL to client
   └─> Client opens browser and authenticates

6. User completes SSO in browser
   └─> openvpn-auth-oauth2 receives OAuth2 callback
   └─> Updates auth_control_file: "1" (success) or "0" (fail)

7. OpenVPN detects file change
   └─> Reads auth_control_file
   └─> Accepts or rejects client based on content
```

**IMPORTANT**: In the deferred flow, `CLIENT_CONNECT_DEFER_V2` may or may not be called depending on how quickly the authentication completes and whether OpenVPN uses file monitoring or plugin polling.

---

## Deferred Authentication

### Understanding Deferred Authentication

Deferred authentication is OpenVPN's mechanism for **asynchronous authentication**. This is essential for:
- SSO/OAuth2 flows (user must complete web authentication)
- Two-factor authentication requiring external systems
- Any authentication that cannot complete immediately

### Two Mechanisms for Deferred Auth

OpenVPN supports TWO ways to complete deferred authentication:

#### Method 1: Auth Control File (File-based)
The plugin writes to files that OpenVPN monitors:

**Files:**
- `auth_control_file` - Final result: "1" (accept), "0" (deny), or "2" (pending)
- `auth_pending_file` - Pending auth info (URL, timeout, message)

**Flow:**
1. Plugin writes "2" to `auth_control_file` → returns DEFERRED
2. OpenVPN shows pending message to client
3. External process (openvpn-auth-oauth2) updates `auth_control_file` when done
4. OpenVPN **monitors file changes** and completes auth when file is updated

#### Method 2: Plugin Polling (CLIENT_CONNECT_DEFER_V2)
OpenVPN repeatedly calls the plugin to check status:

**Flow:**
1. Plugin returns DEFERRED from AUTH_USER_PASS_VERIFY
2. OpenVPN calls `CLIENT_CONNECT_DEFER_V2` **repeatedly** (polling)
3. Plugin checks if auth is complete:
   - Return DEFERRED if still pending
   - Return SUCCESS if completed successfully
   - Return ERROR if failed
4. Process repeats until non-DEFERRED status returned

### Our Implementation Choice

We primarily use **Method 1 (File-based)** because:
- openvpn-auth-oauth2 already updates auth control files
- File monitoring is more efficient than polling
- Simpler state management
- Better integration with existing code

However, we **must still handle** `CLIENT_CONNECT_DEFER_V2` because:
- OpenVPN may call it even with file-based deferred auth
- Different OpenVPN versions behave differently
- The callback is mandatory once registered in type_mask

### Critical Issue Found

After analyzing `sample-client-connect.c`, we found that our `CLIENT_CONNECT_DEFER_V2` implementation was incomplete:

**Problems:**
1. ❌ No per-client context tracking
2. ❌ Just returns SUCCESS immediately (doesn't actually poll)
3. ❌ Doesn't check if authentication completed

**The sample shows:**
```c
int openvpn_plugin_client_connect_defer_v2(
    struct plugin_context *context,
    struct plugin_per_client_context *pcc,  // <-- Per-client state!
    struct openvpn_plugin_string_list **return_list)
{
    time_t time_left = pcc->sleep_until - time(NULL);

    /* not yet due? */
    if (time_left > 0)
    {
        return OPENVPN_PLUGIN_FUNC_DEFERRED;  // <-- Keep polling
    }

    // Check status and return SUCCESS or ERROR
}
```

**Key insight**: OpenVPN provides a `per_client_context` pointer that **persists across multiple calls** for the same client. This is how you track state between polling calls.

### Current Implementation Status

Our current implementation:
- ✅ Properly handles file-based deferred auth
- ✅ Stores deferred client state in `deferredClients` sync.Map
- ⚠️ `CLIENT_CONNECT_DEFER_V2` returns SUCCESS immediately
- ⚠️ Doesn't use OpenVPN's per_client_context pointer

**This works because:**
- openvpn-auth-oauth2 updates auth_control_file directly
- OpenVPN detects file changes via monitoring
- Plugin polling may not be needed in this flow

**But should be improved to:**
- Properly utilize per_client_context if OpenVPN provides it
- Check auth completion status when polled
- Return DEFERRED/SUCCESS/ERROR appropriately

---

## Management Interface Protocol

### Protocol Basics

The plugin implements a **subset** of OpenVPN's management interface protocol:

**Connection:**
```
Server: >INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info
```

**Optional Password Auth:**
```
Server: ENTER PASSWORD:
Client: <password>
Server: SUCCESS: password is correct
```

### Commands Implemented

#### Client Authentication Message (Plugin → openvpn-auth-oauth2)

Format sent by plugin:
```
>CLIENT:CONNECT,<client_id>
>CLIENT:ENV,username=alice
>CLIENT:ENV,password=secret123
>CLIENT:ENV,common_name=alice-laptop
>CLIENT:ENV,untrusted_ip=192.168.1.100
>CLIENT:ENV,END
```

#### Response Commands (openvpn-auth-oauth2 → Plugin)

**Immediate Accept (no config):**
```
client-auth-nt <cid> <kid>
```

**Accept with Config:**
```
client-auth <cid> <kid>
push "route 10.0.0.0 255.255.255.0"
override-username "alice@example.com"
END
```

**Deny:**
```
client-deny <cid> <kid> "Invalid credentials"
```

**Pending (SSO):**
```
client-pending-auth <cid> <kid> "WEB_AUTH::https://sso.example.com/auth?session=xyz" 300
```

Where:
- `<cid>` = Client ID (internal counter from plugin)
- `<kid>` = Key ID (from OpenVPN environment)

### Utility Commands

- `version` - Returns version info
- `hold release` - No-op (compatibility)
- `help` - Shows help
- `quit` / `exit` - Closes connection

---

## File Structure

### Core Files

#### `plugin.go`
Main plugin implementation with CGo bindings.

**Key functions:**
- `openvpn_plugin_open_v3_go()` - Initialize plugin
- `openvpn_plugin_func_v3_go()` - Event dispatcher
- `handleAuthUserPassVerify()` - Main auth logic
- `handleClientConnect()` - Client connection handler
- `handleClientConnectDefer()` - Deferred auth polling

#### `main.go`
Plugin context structures and state management.

**Structures:**
```go
type pluginHandle struct {
    ctx              context.Context
    cancel           context.CancelFunc
    logger           *slog.Logger
    managementClient *management.Server
    cache            *cache.Cache
    deferredClients  sync.Map  // Deferred auth state
}

type deferredClientState struct {
    clientID     uint64
    client       *client.Client
    authResponse *management.Response
    completedAt  time.Time
}
```

#### `callbacks.go`
Auth file writing logic.

**Functions:**
- `writeToAuthFile()` - Writes final auth result
- `writeAuthPending()` - Writes deferred auth info

#### `logger.go`
OpenVPN logging integration via callbacks.

#### `management/management.go`
Management interface server implementation.

**Key components:**
- Socket listener (TCP/Unix)
- Password authentication
- Command parsing
- Response handling

#### `client/client.go`
OpenVPN client environment parsing.

**Converts:**
```
C array of strings → Go Client struct
```

#### `cache/cache.go`
Client state cache with automatic cleanup.

---

## Critical Implementation Details

### CGo Integration

The plugin uses CGo to interface with OpenVPN's C API:

```go
/*
#cgo CFLAGS: -I./include
#include <openvpn-plugin.h>

extern int openvpn_plugin_open_v3(...) {
    return openvpn_plugin_open_v3_go(...);
}
*/
import "C"
```

**Important:**
- `//export` directive makes Go functions callable from C
- Function names must match exact OpenVPN expectations
- Pointers must be carefully converted between C and Go
- Memory management is critical (who owns what?)

### Environment Variable Parsing

OpenVPN passes client info via environment variables:

**Critical variables:**
- `username` - Client username
- `password` - Client password
- `common_name` - Certificate CN
- `untrusted_ip` - Client IP address
- `auth_control_file` - File for auth result
- `auth_pending_file` - File for pending auth info
- Many more...

**Our parser:**
```go
func NewClient(envArray EnvVarsArray) (*Client, error)
```

Converts NULL-terminated C string array to Go map.

### Auth Control Files

OpenVPN creates temporary files for each client auth attempt:

**auth_control_file format:**
```
1                    # Accept
0                    # Deny
0\nReason message   # Deny with reason
2                    # Deferred (pending)
```

**auth_pending_file format:**
```
2
WEB_AUTH::https://sso.example.com/auth?session=abc123
300
```
Line 1: Status code (2 = pending)
Line 2: Message (URL for SSO)
Line 3: Timeout in seconds

### Socket Management

The plugin creates a socket for openvpn-auth-oauth2 to connect:

**TCP Socket:**
```go
addr: "tcp://127.0.0.1:9000"
```

**Unix Socket:**
```go
addr: "unix:///var/run/openvpn-oauth2.sock"
```

**Important:**
- Socket must be created AFTER OpenVPN drops privileges
- Unix sockets need proper permissions
- TCP sockets should bind to localhost only
- Always use password authentication

### Concurrency and Thread Safety

**Challenges:**
1. Plugin callbacks are called from OpenVPN's threads
2. Management interface runs in separate goroutines
3. Multiple clients can authenticate simultaneously

**Solutions:**
- `sync.Map` for deferred client tracking (concurrent safe)
- `sync.Mutex` in management server for connection state
- Channel-based communication for responses
- Atomic operations for connection counting

### Memory Management

**Critical concerns:**
1. **Plugin handle** - Created in `openvpn_plugin_open_v3`, freed in `close_v1`
2. **Per-client context** - OpenVPN may provide per_client_context pointer
3. **C string conversions** - `C.GoString()` copies, original still owned by C
4. **Return values** - Some structs must be allocated and freed properly

**Current approach:**
- Plugin handle is a Go struct, passed as opaque pointer to C
- We don't currently use OpenVPN's per_client_context
- All C strings are immediately converted to Go strings
- No manual memory allocation for return values (yet)

---

## Known Limitations

### 1. Incomplete CLIENT_CONNECT_DEFER_V2 Implementation

**Issue:** Current implementation doesn't properly handle repeated polling.

**Impact:**
- May not work correctly if OpenVPN uses plugin polling instead of file monitoring
- Different OpenVPN versions may behave differently

**Workaround:**
- File-based deferred auth works correctly
- openvpn-auth-oauth2 updates auth files directly

**Fix needed:**
- Implement proper per-client context tracking
- Check auth completion status when polled
- Return appropriate status codes

### 2. No Per-Client Context Usage

**Issue:** OpenVPN provides `per_client_context` pointer, we don't use it.

**Impact:**
- Can't track client state across plugin calls using OpenVPN's mechanism
- Must rely on our own `deferredClients` map

**Workaround:**
- Our sync.Map works fine for now
- Matches clients by ID

**Fix needed:**
- Utilize OpenVPN's per_client_context for proper integration
- Store deferredClientState pointer in per_client_context

### 3. No CLIENT_CONNECT_V2 Config Return

**Issue:** We don't populate `openvpn_plugin_string_list` return value.

**Impact:**
- Can't return client configuration from CLIENT_CONNECT_V2 event
- All config must come through openvpn-auth-oauth2

**Workaround:**
- openvpn-auth-oauth2 sends config via management protocol
- Plugin writes to auth files

**Fix needed:**
- Implement return list population if needed
- May not be necessary for our use case

### 4. Limited Management Protocol

**Issue:** Only implements auth-related commands.

**Impact:**
- Can't use for general OpenVPN management
- No pass-through to real management interface

**Workaround:**
- Use OpenVPN's real management interface for non-auth operations
- That's the whole point of this plugin!

### 5. Experimental Status

**Issue:** Plugin is marked as experimental/WIP.

**Impact:**
- Not recommended for production use yet
- May have undiscovered bugs
- API may change

**Workaround:**
- Thorough testing required
- Use at your own risk

---

## Troubleshooting Guide

### Plugin Fails to Load

**Symptoms:**
```
OpenVPN ERROR: plugin failed to initialize
```

**Causes:**
1. Invalid socket address format
2. Port already in use
3. Permission denied (Unix socket)
4. Missing plugin file

**Debug:**
```bash
# Check OpenVPN logs
journalctl -u openvpn@server -f

# Test socket manually
nc -l 127.0.0.1 9000  # See if port is available

# Check file permissions
ls -la /usr/lib/openvpn/plugins/openvpn-auth-oauth2.so
```

**Fix:**
- Verify socket address syntax
- Use different port
- Fix Unix socket permissions
- Rebuild plugin

### openvpn-auth-oauth2 Can't Connect

**Symptoms:**
```
unable to connect to openvpn management interface tcp://127.0.0.1:9000
```

**Causes:**
1. Plugin not loaded
2. Wrong address in config
3. Firewall blocking
4. Wrong password

**Debug:**
```bash
# Check if socket is listening
netstat -tlnp | grep 9000
lsof -i :9000

# Test connection
telnet 127.0.0.1 9000
```

**Fix:**
- Ensure OpenVPN loaded plugin successfully
- Match addresses in both configs
- Check firewall rules
- Verify password matches

### Authentication Timeouts

**Symptoms:**
```
Client connection times out during authentication
```

**Causes:**
1. openvpn-auth-oauth2 not running
2. OAuth2 provider unreachable
3. Client doesn't support deferred auth
4. Auth files not writable

**Debug:**
```bash
# Check openvpn-auth-oauth2 logs
journalctl -u openvpn-auth-oauth2 -f

# Check auth file permissions
ls -la /tmp/openvpn/

# Test with simple auth (no SSO)
# Check if issue is with deferred auth specifically
```

**Fix:**
- Start openvpn-auth-oauth2
- Check OAuth2 provider connectivity
- Use client that supports deferred auth
- Fix directory permissions

### Deferred Auth Not Working

**Symptoms:**
```
Client doesn't receive SSO URL
```

**Causes:**
1. auth_pending_file not created
2. Wrong file permissions
3. Client doesn't support pending auth
4. OpenVPN version too old

**Debug:**
```bash
# Check if files are created
ls -la /tmp/openvpn/openvpn_*

# Check file contents
cat /tmp/openvpn/openvpn_cc_*
cat /tmp/openvpn/openvpn_acf_*
```

**Fix:**
- Ensure OpenVPN 2.5+ for best support
- Use client that supports deferred auth
- Check plugin logs for file write errors

### Memory Leaks or Crashes

**Symptoms:**
```
OpenVPN crashes or grows memory over time
```

**Causes:**
1. CGo memory management issues
2. Unclosed connections
3. Cache not cleaning up
4. Race conditions

**Debug:**
```bash
# Build with race detector
go build -race -buildmode=c-shared

# Monitor memory
watch -n 1 'ps aux | grep openvpn'

# Enable verbose logging
# Check for repeated errors
```

**Fix:**
- Review CGo pointer handling
- Ensure proper cleanup in close functions
- Fix race conditions
- Check cache cleanup logic

---

## Future Improvements

### High Priority

1. **Complete CLIENT_CONNECT_DEFER_V2 Implementation**
   - Use OpenVPN's per_client_context
   - Properly handle polling
   - Check auth completion status
   - Return correct status codes

2. **Better Error Handling**
   - More detailed error messages
   - Error codes for debugging
   - Retry logic for transient failures

3. **Testing**
   - Unit tests for all components
   - Integration tests with real OpenVPN
   - Load testing
   - Edge case testing

### Medium Priority

4. **Configuration Validation**
   - Validate socket addresses at startup
   - Check file permissions early
   - Warn about misconfigurations

5. **Metrics and Monitoring**
   - Prometheus metrics
   - Auth success/failure rates
   - Connection counts
   - Latency tracking

6. **Documentation**
   - More examples
   - Video tutorials
   - Common deployment scenarios

### Low Priority

7. **CLIENT_CONNECT_V2 Return List**
   - Implement config return if needed
   - May not be necessary

8. **Additional Management Commands**
   - More compatibility commands
   - Status queries
   - Statistics

9. **Windows Support**
   - Test on Windows
   - Fix platform-specific issues
   - Windows socket handling

---

## Development Tips

### Building

```bash
cd lib/openvpn-plugin
make build
```

### Testing

```bash
# Unit tests
go test -v ./...

# Build with race detector
make build-debug

# Test with OpenVPN
sudo openvpn --config test-server.conf
```

### Debugging

```bash
# Enable verbose logging in OpenVPN
verb 6

# Add debug logs to plugin
p.logger.Debug("detailed message", slog.String("key", value))

# Use delve for debugging
dlv exec /usr/sbin/openvpn -- --config server.conf
```

### Code Style

- Follow existing patterns
- Use `//goland:noinspection` for unavoidable warnings
- Add comments for CGo interfaces
- Document exported functions
- Keep functions focused and small

---

## References

### Official Documentation

- [OpenVPN Plugin API](https://github.com/OpenVPN/openvpn/blob/master/doc/plugin-api.rst)
- [OpenVPN Management Interface](https://github.com/OpenVPN/openvpn/blob/master/doc/management-notes.txt)
- [CGo Documentation](https://golang.org/cmd/cgo/)

### Sample Code

- `sample-client-connect.c` - Official OpenVPN plugin example
- OpenVPN source: `sample/sample-plugins/` directory
- This implementation: All files in `lib/openvpn-plugin/`

### Related Projects

- [openvpn-auth-oauth2](https://github.com/jkroepke/openvpn-auth-oauth2) - Main project
- [OpenVPN](https://github.com/OpenVPN/openvpn) - OpenVPN source

---

## Conclusion

This plugin successfully bridges OpenVPN's plugin API with openvpn-auth-oauth2's management interface protocol, allowing OAuth2/SSO authentication without blocking OpenVPN's management interface for other uses.

The implementation is functional but has room for improvements, particularly in the deferred authentication polling mechanism. The file-based deferred auth works correctly, which is the primary use case for SSO authentication.

For questions or contributions, see the main project repository and documentation.
