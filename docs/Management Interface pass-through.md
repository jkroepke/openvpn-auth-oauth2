# OpenVPN Management Interface Pass-through in openvpn-auth-oauth2

The OpenVPN management interface pass-through feature in openvpn-auth-oauth2 is designed to allow existing OpenVPN frontends to continue functioning while openvpn-auth-oauth2 is running. This feature is particularly useful because the OpenVPN daemon can support at most a single management client at any one time, and this feature has the same limitation.

## How it Works

openvpn-auth-oauth2 acts as a middleman, forwarding commands and responses between the frontend and the OpenVPN management interface. This allows the frontend to control and monitor the OpenVPN server as if it were directly connected to the management interface.

## Configuration

You can configure the pass-through feature via the command line interface (CLI) using the following options:

```bash
--openvpn.pass-through.enabled
--openvpn.pass-through.address
--openvpn.pass-through.password
--openvpn.pass-through.socket-group
--openvpn.pass-through.socket-mode
```

For example:

```bash
openvpn-auth-oauth2 --openvpn.pass-through.enabled=true --openvpn.pass-through.address=unix:///run/openvpn/pass-through.sock
```

## Command Filtering

openvpn-auth-oauth2 filters certain commands for security reasons. The following commands are not allowed and will be filtered:

- `client-deny`
- `client-auth`
- `client-auth-nt`

If a client sends one of these commands, openvpn-auth-oauth2 will respond with "ERROR: command not allowed" and log a warning message.

