# OpenVPN Plugin

> [!NOTE]
> The OpenVPN plugin is stable and supported since openvpn-auth-oauth2 version
> 2.0. It is a production deployment option, not an experimental feature.

The plugin connects OpenVPN Server to the `openvpn-auth-oauth2` service through
OpenVPN's plugin API. It exposes the authentication events that
`openvpn-auth-oauth2` needs without occupying OpenVPN's management interface.
Monitoring, administration, or other management clients can continue using the
real management interface.

## When to use the plugin

Use the plugin when:

- the OpenVPN server runs on Linux AMD64, Linux ARM64, or FreeBSD AMD64;
- another tool needs OpenVPN's management interface; or
- you prefer to isolate authentication from general management commands.

Use the [direct management interface](Configuration#direct-management-interface)
instead when `openvpn.enforce-unique-user` is required.

| Capability | Plugin |
| --- | --- |
| Browser-based OIDC authentication | Supported |
| Non-interactive session refresh | Supported |
| `openvpn.override-username` | Supported on OpenVPN 2.7 or later |
| Built-in client-specific configuration | Supported |
| `openvpn.enforce-unique-user` | Not supported; use the direct management interface |
| General OpenVPN management commands | Use OpenVPN's separate, real management interface |

> [!IMPORTANT]
> `openvpn.enforce-unique-user` does not work through the plugin. The setting
> queries `status 3` and sends `client-kill` before accepting a connection. The
> plugin socket deliberately implements only the authentication-related
> management protocol, so `openvpn-auth-oauth2` rejects this combination during
> startup.

## Architecture

```text
┌─────────────────────────┐
│ OpenVPN Server          │
│                         │
│ Real management socket  │<── monitoring or administration tools
└────────────┬────────────┘
             │ OpenVPN plugin API
┌────────────▼────────────┐
│ openvpn-auth-oauth2.so  │
└────────────┬────────────┘
             │ Auth-only TCP or Unix socket
┌────────────▼────────────┐
│ openvpn-auth-oauth2     │
└─────────────────────────┘
```

## Requirements

- OpenVPN Community Server 2.6.2 or later.
- Linux AMD64, Linux ARM64, or FreeBSD AMD64 for a prebuilt plugin artifact.
- The `openvpn-auth-oauth2` binary and plugin from the same release.
- A dedicated password shared by the OpenVPN plugin and
  `openvpn-auth-oauth2`.

> [!NOTE]
> Release archives contain the plugin for Linux AMD64, Linux ARM64, and FreeBSD
> AMD64. Linux AMD64 and ARM64 DEB/RPM packages also contain the matching
> plugin. The `openvpn-auth-oauth2` service itself is released for more operating
> systems and architectures; those other artifacts do not include the plugin.

## 1. Install the plugin

Linux DEB and RPM packages install the shared library that matches the package
architecture. On every supported platform, the shared library is named
`openvpn-auth-oauth2.so`. Release archives contain the plugin beside the service
binary, and Linux packages install it at:

```text
/usr/lib/openvpn/openvpn-auth-oauth2.so
```

If you use the release archive, extract the matching `.so` file and place it in
a directory that OpenVPN can read. Keep the plugin and service versions aligned.

## 2. Create the connection password

Package installations confine OpenVPN and `openvpn-auth-oauth2` differently.
Use two files with identical contents so each process can read its own file
without broadening filesystem access:

```bash
sudo install -m 0600 -o root -g root /dev/null \
  /etc/openvpn/management-password.txt
sudo install -m 0640 -o root -g openvpn-auth-oauth2 /dev/null \
  /etc/openvpn-auth-oauth2/management-password.txt
plugin_password="$(openssl rand -hex 32)"
printf '%s\n' "$plugin_password" \
  | sudo tee /etc/openvpn/management-password.txt \
    /etc/openvpn-auth-oauth2/management-password.txt >/dev/null
unset plugin_password
```

> [!WARNING]
> The plugin socket controls authentication decisions. Do not expose it to an
> untrusted network, and do not make either password file readable by unrelated
> users.

## 3. Configure OpenVPN

### TCP loopback socket

TCP loopback avoids Unix socket ownership differences between OpenVPN packages:

```ini
plugin /usr/lib/openvpn/openvpn-auth-oauth2.so "tcp://127.0.0.1:9002" "/etc/openvpn/management-password.txt"
auth-user-pass-optional
```

### Unix socket

A Unix socket avoids allocating a TCP port:

```ini
plugin /usr/lib/openvpn/openvpn-auth-oauth2.so "unix:///run/openvpn/openvpn-auth-oauth2.sock" "/etc/openvpn/management-password.txt"
auth-user-pass-optional
```

> [!IMPORTANT]
> For a Unix socket, OpenVPN must be able to create the socket before dropping
> privileges and remove it during shutdown. The runtime user therefore needs
> write and search permissions on the parent directory.

The plugin directive accepts three values:

1. Path to the shared library.
2. TCP or Unix address on which the plugin listens for
   `openvpn-auth-oauth2`.
3. Path to the password file that OpenVPN can read.

Restart the applicable OpenVPN server unit after changing its configuration.

## 4. Configure openvpn-auth-oauth2

Set `openvpn.addr` to the same address as the plugin and read the matching
password copy.

### YAML configuration

```yaml
openvpn:
  addr: "tcp://127.0.0.1:9002"
  password: "file:///etc/openvpn-auth-oauth2/management-password.txt"
```

### Environment configuration

```ini
OPENVPN_AUTH_OAUTH2_OPENVPN_ADDR=tcp://127.0.0.1:9002
OPENVPN_AUTH_OAUTH2_OPENVPN_PASSWORD=file:///etc/openvpn-auth-oauth2/management-password.txt
```

For a Unix socket, replace the address in both configurations with the same
`unix://` value.

> [!TIP]
> To avoid browser logins during TLS reauthentication and reconnects, configure
> [non-interactive session refresh](Non-interactive%20session%20refresh). The
> plugin supports refresh tokens and OpenVPN session IDs.

## 5. Verify the connection

Start or restart `openvpn-auth-oauth2`, then inspect both services:

```bash
sudo systemctl restart openvpn-auth-oauth2
sudo systemctl status openvpn-auth-oauth2
sudo journalctl -u openvpn-auth-oauth2 --no-pager -n 100
```

The `openvpn-auth-oauth2` log should report a connection to the configured
address. The OpenVPN log should show that the plugin loaded without an address,
password-file, or permission error.

If the connection fails, verify that:

- OpenVPN loaded the `.so` from the expected path;
- both configurations use the same TCP or Unix address;
- the two password files contain the same value; and
- each process can read its password file and access every parent directory.
