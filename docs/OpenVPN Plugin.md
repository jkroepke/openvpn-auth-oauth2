# OpenVPN Plugin

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
# Load the plugin with listen socket address and password file
plugin /path/to/openvpn-auth-oauth2.so "tcp://127.0.0.1:9000" "/etc/openvpn/oauth2-plugin-password.txt"

# Or use Unix socket
plugin /path/to/openvpn-auth-oauth2.so "unix:///var/run/openvpn-oauth2.sock" "/etc/openvpn/oauth2-plugin-password.txt"
```

Plugin arguments:
1. **Listen socket** (required): The address where the management interface will listen
  - TCP: `tcp://host:port` (e.g., `tcp://127.0.0.1:9000`)
  - Unix: `unix:///path/to/socket` (e.g., `unix:///var/run/openvpn-oauth2.sock`)
2. **Password file** (required): File containing the management interface password

For package installations, the shipped AppArmor profile allows
`openvpn-auth-oauth2` to read `/etc/openvpn-auth-oauth2/**`, while OpenVPN
installations commonly keep plugin-readable files below `/etc/openvpn/`.
Use two dedicated password files with identical contents instead of making one
file readable across both confined contexts:

- `/etc/openvpn/oauth2-plugin-password.txt` for the OpenVPN plugin argument.
- `/etc/openvpn-auth-oauth2/oauth2-plugin-password.txt` for
  `openvpn-auth-oauth2`.

Create each file with restrictive ownership and permissions for the process that
must read it, for example mode `0640` with the appropriate service group.

### openvpn-auth-oauth2 Configuration

Configure openvpn-auth-oauth2 to connect to the plugin's management socket instead of OpenVPN's:

<table>
<thead><tr><td>env/sysconfig configuration</td></tr></thead>
<tbody><tr><td>

```ini
CONFIG_OPENVPN_ADDR=unix:///var/run/openvpn-oauth2.sock
CONFIG_OPENVPN_PASSWORD=file:///etc/openvpn-auth-oauth2/oauth2-plugin-password.txt
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
  password: "file:///etc/openvpn-auth-oauth2/oauth2-plugin-password.txt"
oauth2:
  refresh:
    enabled: true
    expires: 8h
    secret: "..." # 16 or 24 characters
    use-session-id: true
```
</td></tr></tbody>
</table>
