# OpenVPN Plugin Shim

This plugin acts as a shim between OpenVPN Server and openvpn-auth-oauth2, allowing the authentication service to connect via a management interface socket instead of directly to OpenVPN's management interface. This prevents blocking the management interface for other purposes.

## Overview

The plugin provides a subset of the OpenVPN management interface protocol, supporting only auth-related functions:
- `client-auth` - Accept client with optional configuration
- `client-auth-nt` - Accept client without additional configuration
- `client-deny` - Deny client with reason
- `client-pending-auth` - Defer authentication (for SSO/web auth flows)

## Architecture

```
┌─────────────────┐
│  OpenVPN Server │
└────────┬────────┘
         │ (plugin interface)
         │
┌────────▼────────────────────┐
│  openvpn-auth-oauth2.so     │  <-- This Plugin
│  (Plugin Shim)              │
└────────┬────────────────────┘
         │ (management socket)
         │
┌────────▼────────────────────┐
│  openvpn-auth-oauth2        │  <-- Main Auth Service
│  (OAuth2 Authentication)    │
└─────────────────────────────┘
```

## Building

Build the plugin as a shared library:

```bash
cd lib/openvpn-plugin
go build -buildmode=c-shared -o openvpn-auth-oauth2.so
```

## Configuration

### OpenVPN Server Configuration

Add the plugin to your OpenVPN server configuration:

```
# Load the plugin with listen socket address and optional password
plugin /path/to/openvpn-auth-oauth2.so "tcp://127.0.0.1:9000" "optional-password"

# Or use Unix socket
plugin /path/to/openvpn-auth-oauth2.so "unix:///var/run/openvpn-oauth2.sock"
```

Plugin arguments:
1. **Listen socket** (required): The address where the management interface will listen
   - TCP: `tcp://host:port` (e.g., `tcp://127.0.0.1:9000`)
   - Unix: `unix:///path/to/socket` (e.g., `unix:///var/run/openvpn-oauth2.sock`)
2. **Password** (optional): Password for management interface authentication

### openvpn-auth-oauth2 Configuration

Configure openvpn-auth-oauth2 to connect to the plugin's management socket instead of OpenVPN's:

```yaml
openvpn:
  addr: tcp://127.0.0.1:9000
  password: "optional-password"  # Must match plugin password if set

  # Disable passthrough since we're not connected to the real OpenVPN management interface
  passthrough:
    enabled: false
```

## Supported Commands

The plugin implements the following management interface commands:

### Client Authentication Commands

- **version** - Returns version information
- **hold release** - Releases hold state (no-op in plugin)
- **help** - Shows help message
- **quit/exit** - Closes connection

### Client-specific Commands (sent by openvpn-auth-oauth2)

- **client-auth CID KID** - Accept client with optional config (multi-line with END)
- **client-auth-nt CID KID** - Accept client without config
- **client-deny CID KID "reason"** - Deny client with reason
- **client-pending-auth CID KID "WEB_AUTH::URL" timeout** - Defer auth for SSO

Where:
- `CID` = Client ID (internal counter)
- `KID` = Key ID (from OpenVPN environment)

## Plugin Events Handled

The plugin handles these OpenVPN plugin events:

- **OPENVPN_PLUGIN_UP** - Server is ready
- **OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY** - Authenticate user credentials
- **OPENVPN_PLUGIN_CLIENT_CONNECT_V2** - Client connecting (optional config)
- **OPENVPN_PLUGIN_CLIENT_CONNECT_DEFER_V2** - Deferred client connect

## Authentication Flow

1. OpenVPN calls `OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY` with client environment
2. Plugin creates client object and sends to management interface: `>CLIENT:CONNECT,<cid>\r\n>CLIENT:ENV,key=value...\r\n>CLIENT:ENV,END`
3. openvpn-auth-oauth2 receives client info and processes authentication
4. openvpn-auth-oauth2 responds with:
   - `client-auth-nt CID KID` - Immediate accept
   - `client-deny CID KID "reason"` - Immediate deny
   - `client-pending-auth CID KID "WEB_AUTH::url" 300` - Deferred (SSO)
5. Plugin writes result to OpenVPN auth control files
6. For deferred auth, openvpn-auth-oauth2 later updates the auth files when user completes SSO

## Deferred Authentication

For SSO/web authentication flows:

1. Plugin writes `2` to `auth_control_file` (deferred)
2. Plugin writes pending info to `auth_pending_file`:
   ```
   2
   https://sso.example.com/auth?session=xyz
   300
   ```
3. OpenVPN shows this URL to the client
4. When user completes auth, openvpn-auth-oauth2 writes `1` (accept) or `0` (deny) to the control file

## Logging

The plugin uses OpenVPN's logging callback system. Log messages appear in OpenVPN's log with appropriate severity levels:

- INFO - Normal operations
- WARN - Non-fatal issues
- ERROR - Fatal errors
- DEBUG - Detailed debugging (if OpenVPN configured with appropriate log level)

## Limitations

⚠️ **EXPERIMENTAL**: This plugin is still in experimental state.

- Only supports auth-related management commands
- Does not support full management interface pass-through
- Client configuration (CCD) must be handled by openvpn-auth-oauth2
- No support for dynamic challenge/response beyond basic pending auth

## Troubleshooting

### Plugin fails to load

Check OpenVPN logs for initialization errors:
- Verify socket address format is correct
- Ensure port is not already in use
- Check file permissions for Unix sockets

### Authentication timeouts

- Verify openvpn-auth-oauth2 can connect to the management socket
- Check password matches between plugin and openvpn-auth-oauth2 config
- Review both OpenVPN and openvpn-auth-oauth2 logs

### Deferred auth not working

- Ensure OpenVPN client supports deferred auth
- Check that `auth_pending_file` is being created
- Verify openvpn-auth-oauth2 has permission to write to auth control files

## Security Considerations

- **TCP sockets**: Use firewall rules to restrict access to localhost only
- **Unix sockets**: Set appropriate file permissions
- **Password**: Always set a password when using TCP sockets
- **No encryption**: The management protocol is not encrypted; use Unix sockets or localhost binding for security

## Development

See [DEVELOPER.md](../../DEVELOPER.md) for development guidelines.

### Testing

Run tests:
```bash
go test -v ./lib/openvpn-plugin/...
```

Build with debug symbols:
```bash
go build -buildmode=c-shared -gcflags="all=-N -l" -o openvpn-auth-oauth2.so
```

## License

See [LICENSE.txt](../../LICENSE.txt)
