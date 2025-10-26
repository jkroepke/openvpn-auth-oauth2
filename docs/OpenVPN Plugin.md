# OpenVPN Plugin

> [!IMPORTANT]
> This state is experimental.

This plugin acts as a shim between OpenVPN Server and openvpn-auth-oauth2, allowing the authentication service to connect via a management interface socket instead of directly to OpenVPN's management interface. This prevents blocking the management interface for other purposes.

Due limitation on Go site, this plugin runs only under Linux.

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

<table>
<thead><tr><td>env/sysconfig configuration</td></tr></thead>
<tbody><tr><td>

```ini
CONFIG_OPENVPN_ADDR=unix:///var/run/openvpn-oauth2.sock
CONFIG_OPENVPN_PASSWORD=optional-password
CONFIG_OAUTH2_REFRESH_ENABLED=true
CONFIG_OAUTH2_REFRESH_EXPIRES=8h
CONFIG_OAUTH2_REFRESH_SECRET= # a static secret to encrypt token. Must be 16, 24 or 32
CONFIG_OAUTH2_REFRESH_USE__SESSION__ID=true
CONFIG_OPENVPN_AUTH__TOKEN__USER=true
```
</td></tr></tbody>
<thead><tr><td>yaml configuration</td></tr></thead>
<tbody><tr><td>

```yaml
openvpn:
  addr: unix:///var/run/openvpn-oauth2.sock
  password: "optional-password"  # Must match plugin password if set
oauth2:
  refresh:
    enabled: true
    expires: 8h
    secret: "..." # 16 or 24 characters
    use-session-id: true
```
</td></tr></tbody>
</table>
