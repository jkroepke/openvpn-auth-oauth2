# Getting Started

This guide takes you from an existing OpenVPN Community Server to a first OIDC
login. It uses the Linux package and a reverse proxy on the same host as
`openvpn-auth-oauth2`. You can connect OpenVPN through the stable plugin or
directly through its management interface.

If you only want to evaluate the login flow, use the self-contained
[Docker Compose demo](Demo). For other deployment layouts, follow this guide to
understand the required connections, then use the linked reference pages.

## What you need

- OpenVPN Community Server 2.6.2 or later and a
  [WebAuth-compatible client](OpenVPN).
- Administrator access to an OIDC provider.
- Root access to the OpenVPN server.
- A short public HTTPS URL, such as `https://vpn-login.example.com`, that VPN
  clients can reach.
- A TLS certificate or reverse proxy for that URL.

You will configure three connections:

```text
OpenVPN client  ->  public HTTPS URL  ->  openvpn-auth-oauth2
                                           |
                                           +-> OIDC provider
                                           |
OpenVPN server  <--- plugin or management ---+
```

## 1. Choose the public URL

In the examples below, the public URL is `https://vpn-login.example.com`. The
OIDC redirect URI is always the public URL followed by `/oauth2/callback`:

```text
https://vpn-login.example.com/oauth2/callback
```

The public URL must resolve from the user's browser. It does not have to match
the OpenVPN server hostname.

## 2. Install openvpn-auth-oauth2

On a Debian-based system, install the current release from the project's APT
repository:

```bash
curl -L https://raw.githubusercontent.com/jkroepke/openvpn-auth-oauth2/refs/heads/main/packaging/apt/openvpn-auth-oauth2.sources \
  | sudo tee /etc/apt/sources.list.d/openvpn-auth-oauth2.sources
sudo apt update
sudo apt install openvpn-auth-oauth2
```

For RPM packages or a source build, see [Installation](Installation). Do not
start the service yet; it requires the OIDC and OpenVPN settings from the next
steps.

## 3. Register the OIDC application

Create an application in your OIDC provider with the redirect URI from step 1.
Keep these values for the service configuration:

- issuer URL;
- client ID;
- client secret;
- provider name, scopes, or additional settings required by that provider.

Follow the matching section in [Providers](Providers) for exact registration
steps and configuration. If your provider is not listed, use the `generic`
provider with its OIDC issuer URL.

## 4. Choose the OpenVPN integration

Both integration methods support browser authentication, token refresh,
username overrides, and client-specific configuration.

| Integration | Choose it when | Trade-off |
| --- | --- | --- |
| [OpenVPN plugin](OpenVPN%20Plugin) | Your OpenVPN server uses Linux AMD64 | Keeps OpenVPN's management interface available, but cannot enforce one active session per OIDC username |
| Direct management interface | You need `openvpn.enforce-unique-user` or cannot use the plugin | Supports the full management command set, but occupies OpenVPN's single management client connection |

> [!NOTE]
> The OpenVPN plugin is stable and supported since openvpn-auth-oauth2 version
> 2.0. It is not an experimental integration.

## 5. Configure the OpenVPN server

Add the configuration for the integration selected in step 4 to the existing
OpenVPN server configuration. Keep the server's current network, TLS, and PKI
settings.

Create a password for the connection between OpenVPN and
`openvpn-auth-oauth2`. Both processes must use the same value.

```bash
sudo install -m 0600 -o root -g root /dev/null \
  /etc/openvpn/management-password.txt
sudo install -m 0640 -o root -g openvpn-auth-oauth2 /dev/null \
  /etc/openvpn-auth-oauth2/management-password.txt
management_password="$(openssl rand -hex 32)"
printf '%s\n' "$management_password" \
  | sudo tee /etc/openvpn/management-password.txt \
    /etc/openvpn-auth-oauth2/management-password.txt >/dev/null
unset management_password
```

### Option A: OpenVPN plugin

Linux AMD64 DEB and RPM packages install the plugin at
`/usr/lib/openvpn/openvpn-auth-oauth2-linux-amd64.so`. Add it to the OpenVPN
server configuration:

```ini
plugin /usr/lib/openvpn/openvpn-auth-oauth2-linux-amd64.so "tcp://127.0.0.1:9002" "/etc/openvpn/management-password.txt"
auth-user-pass-optional
```

The plugin listens on the loopback address for `openvpn-auth-oauth2` and leaves
OpenVPN's real management interface available for other tools. See
[OpenVPN Plugin](OpenVPN%20Plugin) for Unix socket configuration, package and
architecture limitations, and troubleshooting.

> [!IMPORTANT]
> Do not enable `openvpn.enforce-unique-user` with the plugin. The setting needs
> the `status 3` and `client-kill` commands from OpenVPN's direct management
> interface, which the plugin's authentication-only protocol does not expose.

### Option B: Direct management interface

Add the following directives to the OpenVPN server configuration:

```ini
management /run/openvpn/server.sock unix /etc/openvpn/management-password.txt
management-client-auth
auth-user-pass-optional
```

> [!WARNING]
> The management interface accepts only one client. If another tool needs that
> connection, use the [OpenVPN plugin](OpenVPN%20Plugin) or
> [management interface pass-through](Management%20Interface%20pass-through).

By default, OpenVPN continues to require the client certificates from the
existing server configuration. If browser-based OIDC authentication should
replace client-certificate authentication, add this directive for either
integration:

```ini
verify-client-cert none
```

> [!TIP]
> To avoid another browser login during TLS reauthentication or reconnects,
> configure both the OpenVPN `auth-gen-token` directive and
> [non-interactive session refresh](Non-interactive%20session%20refresh).

Restart the applicable OpenVPN server unit after changing its configuration.
Unit names vary by distribution and instance, so use the name for your existing
server. With the direct management integration, confirm that
`/run/openvpn/server.sock` exists after the restart.

## 6. Configure openvpn-auth-oauth2

Generate a cookie-encryption secret. The value must contain exactly 16, 24, or
32 characters; this command generates 32:

```bash
sudo install -m 0640 -o root -g openvpn-auth-oauth2 /dev/null \
  /etc/openvpn-auth-oauth2/http-secret.txt
openssl rand -hex 16 \
  | sudo tee /etc/openvpn-auth-oauth2/http-secret.txt >/dev/null
```

Edit `/etc/openvpn-auth-oauth2/config.yaml` and add the minimum configuration
below. Replace every value in angle brackets and merge any extra settings from
your provider's documentation.

```yaml
http:
  listen: "127.0.0.1:9000"
  baseurl: "https://vpn-login.example.com"
  secret: "file:///etc/openvpn-auth-oauth2/http-secret.txt"

oauth2:
  issuer: "<oidc-issuer-url>"
  client:
    id: "<oidc-client-id>"
    secret: "<oidc-client-secret>"

openvpn:
  # OpenVPN plugin:
  addr: "tcp://127.0.0.1:9002"
  password: "file:///etc/openvpn-auth-oauth2/management-password.txt"
```

> [!TIP]
> When using the direct management interface, set `openvpn.addr` to
> `unix:///run/openvpn/server.sock` instead.

The package also reads `/etc/sysconfig/openvpn-auth-oauth2`; values there
override the YAML file. The [Configuration](Configuration) reference explains
all settings, precedence, and how to read secrets from files.

## 7. Add HTTPS

Configure your reverse proxy to serve `https://vpn-login.example.com` and
forward requests to `http://127.0.0.1:9000`. The public URL must match
`http.baseurl` exactly.

See [HTTPS Listener](HTTPS%20Listener) for reverse-proxy guidance or for using
the service's native TLS listener. Do not expose the plain HTTP listener to an
untrusted network.

## 8. Start and verify the service

Enable the service and inspect its startup logs:

```bash
sudo systemctl enable --now openvpn-auth-oauth2
sudo systemctl status openvpn-auth-oauth2
sudo journalctl -u openvpn-auth-oauth2 --no-pager -n 100
```

Startup must complete without configuration, OIDC discovery, socket, or
permission errors. If the service cannot read a secret or connect to the Unix
socket, see [Filesystem Permissions](Filesystem%20Permissions).

## 9. Test a VPN login

1. Import the OpenVPN profile into a [supported client](OpenVPN).
2. Connect to the VPN.
3. Confirm that the client opens the public URL in a browser.
4. Sign in at the OIDC provider.
5. Confirm that the browser reports success and the VPN connection completes.

If the browser does not open, authentication loops, or the connection times
out, start with [Troubleshooting](Debugging%20Errors) and the [FAQ](FAQ). Check
the OpenVPN server and `openvpn-auth-oauth2` logs together because the flow
crosses both services.

## Production checklist

After the first successful login:

- Review the [security considerations](Security%20considerations), especially
  IP-address validation and trusted reverse proxies.
- Configure [token validation](Client%20token%20validation) or provider-side
  assignments so only intended users can connect.
- Decide whether users need
  [non-interactive session refresh](Non-interactive%20session%20refresh).
- Review [OpenVPN username handling](OpenVPN%20Username) if logs, status output,
  or per-user policy must use the OIDC identity.
- If only one session per OIDC username is allowed, review the
  [`openvpn.enforce-unique-user` limitations](OpenVPN%20Username#limiting-a-username-to-one-active-session)
  before choosing the OpenVPN integration.
- Keep the HTTP, OIDC client, management, and refresh secrets out of source
  control and restrict their filesystem permissions.
