# OpenVPN Management Interface Pass-through in openvpn-auth-oauth2

The OpenVPN management interface pass-through feature in openvpn-auth-oauth2 is designed to allow existing OpenVPN frontends to continue functioning while openvpn-auth-oauth2 is running. This feature is particularly useful because the OpenVPN daemon can support at most a single management client at any one time, and this feature has the same limitation.

## How it Works

openvpn-auth-oauth2 acts as a middleman, forwarding commands and responses between the frontend and the OpenVPN management interface. This allows the frontend to control and monitor the OpenVPN server as if it were directly connected to the management interface.

## Configuration

You can configure the pass-through feature  using the following options:

<table>
<thead><tr><td>CLI configuration</td></tr></thead>
<tbody><tr><td>

```bash
openvpn-auth-oauth2 \
  --openvpn.pass-through.enabled=true \
  --openvpn.pass-through.address=unix:///run/openvpn/pass-through.sock  \
  --openvpn.pass-through.password=secret
  # --openvpn.pass-through.socket-group=openvpn-auth-oauth2 # optional
  # --openvpn.pass-through.socket-mode=0660 # optional
```
</td></tr></tbody>
<thead><tr><td>env/sysconfig configuration</td></tr></thead>
<tbody><tr><td>

```ini
CONFIG_OPENVPN_PASS__THROUGH_ENABLED=true
CONFIG_OPENVPN_PASS__THROUGH_ADDRESS=unix:///run/openvpn/pass-through.sock
CONFIG_OPENVPN_PASS__THROUGH_PASSWORD=secret
# CONFIG_OPENVPN_PASS__THROUGH_SOCKET__GROUP=openvpn-auth-oauth2 # optional
# CONFIG_OPENVPN_PASS__THROUGH_SOCKET__MODE=0660 # optional
```
</td></tr></tbody>
<thead><tr><td>yaml configuration</td></tr></thead>
<tbody><tr><td>

```yaml
openvpn:
  pass-through:
    enabled: true
    address: "unix:///run/openvpn/pass-through.sock"
    password: "secret"
    #socket-group: "openvpn-auth-oauth2" # optional
    #socket-mode: 660 # optional
```
</td></tr></tbody>
</table>

## Command Filtering

openvpn-auth-oauth2 filters certain commands for security reasons. The following commands are not allowed and will be filtered:

- `client-deny`
- `client-auth`
- `client-auth-nt`

If a client sends one of these commands, openvpn-auth-oauth2 will respond with "ERROR: command not allowed" and log a warning message.

