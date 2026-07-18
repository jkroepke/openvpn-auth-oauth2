# Duplicate username sessions

`openvpn.kill-duplicate-username` limits a resolved SSO username to one active
OpenVPN client session. When a new client authenticates with a username that is
already associated with another client, `openvpn-auth-oauth2` asks OpenVPN to
terminate the previous client before accepting the new one.

This is useful when different client certificates or certificate common names
can authenticate as the same SSO user.

# Relationship to `duplicate-cn`

OpenVPN normally disconnects an existing client when another client connects with
the same certificate common name. The OpenVPN
[`duplicate-cn`](https://github.com/OpenVPN/openvpn/blob/master/doc/man-sections/server-options.rst)
option disables that restriction and permits multiple clients with the same
common name to connect concurrently.

`openvpn.kill-duplicate-username` applies OpenVPN's default single-session
replacement model to the SSO username:

| OpenVPN behavior | Identity used for comparison | Result |
| --- | --- | --- |
| `duplicate-cn` is not configured | Certificate common name | A new same-CN client replaces the existing client |
| `duplicate-cn` is configured | Certificate common name | Multiple same-CN clients can remain connected |
| `openvpn.kill-duplicate-username=true` | Resolved SSO username | A new same-username client replaces the existing client |

The settings are independent. `openvpn.kill-duplicate-username` does not change
OpenVPN's `duplicate-cn` configuration and does not use the certificate common
name as its primary identity. It adds duplicate detection after successful SSO
authentication, when the SSO username is known.

For example, clients with certificate common names `laptop` and `phone` may both
authenticate as `alice`. OpenVPN does not consider those common names duplicates.
With `openvpn.kill-duplicate-username=true`, the client that authenticates second
as `alice` replaces the first one.

# Shared client profile with placeholder credentials

A deployment may distribute one `.ovpn` profile to every user and include
placeholder credentials to prevent the OpenVPN client from displaying a
username-and-password prompt:

```text
<auth-user-pass>
username
pass
</auth-user-pass>
```

The placeholder values are not the user's identity or authentication secret. The
user authenticates through the browser-based OAuth2 flow, and an OIDC provider
such as Keycloak supplies the real username.

In a setup that uses `username-as-common-name`, every connection initially has
the same common name, such as `username`. OpenVPN must permit that shared
placeholder so different SSO users can connect at the same time. Configuring
`duplicate-cn` provides that behavior, but it also means OpenVPN does not enforce
one session per real SSO user.

Settings such as `openvpn.auth-token-user=true` and
`openvpn.override-username=true` can expose the resolved SSO username to OpenVPN
after authentication. However, changing the username after authentication does
not repeat OpenVPN's earlier common-name duplicate decision. Without additional
handling, a second device can authenticate as the same SSO user and remain
connected alongside the first device.

Enable SSO username replacement for this setup:

```yaml
openvpn:
  auth-token-user: true
  override-username: true
  kill-duplicate-username: true
```

The resulting behavior distinguishes real users while retaining the shared
profile:

1. Alice's laptop connects with the placeholder and authenticates as `alice`.
2. Bob's laptop connects with the same placeholder and authenticates as `bob`.
   Both clients remain connected because their SSO usernames differ.
3. Alice's phone connects with the same placeholder and authenticates as `alice`.
4. `openvpn-auth-oauth2` terminates Alice's laptop session before accepting her
   phone. Bob's session is unaffected.

`openvpn.override-username` requires OpenVPN 2.7 and is useful for displaying the
real username in OpenVPN. Duplicate replacement does not depend on OpenVPN
detecting that overridden value; `openvpn-auth-oauth2` uses the resolved SSO
username directly.

# How it works

The username is resolved from `oauth2.openvpn-username`. After successful
authentication, `openvpn-auth-oauth2` performs these steps:

1. It checks its local username-to-client mapping for an existing owner.
2. If another client owns the username, it sends `client-kill <CID>` through the
   OpenVPN management interface. OpenVPN's
   [`client-kill`](https://github.com/OpenVPN/openvpn/blob/master/doc/management-notes.txt)
   command terminates the client instance identified by its CID.
3. It accepts the new client only after the previous client was terminated
   successfully.
4. It records the new username owner and removes that ownership when the client
   disconnects.

If OpenVPN reports that the stored CID no longer exists, the application removes
the stale ownership record and continues accepting the new client. Other OpenVPN
errors, management connection failures, and command timeouts still prevent
acceptance. This prevents the application from knowingly accepting two clients
for the same tracked username.

# Configuration

Enable the feature in the YAML configuration:

```yaml
openvpn:
  kill-duplicate-username: true
```

Or use the environment variable:

```ini
CONFIG_OPENVPN_KILL__DUPLICATE__USERNAME=true
```

The feature requires a direct OpenVPN management interface that supports
`client-kill`. It is not available when `openvpn-auth-oauth2` connects through the
[OpenVPN plugin](OpenVPN%20Plugin), because that management-interface shim does
not support terminating an established client. Startup fails with an explanatory
error if both modes are configured.

# Scope and limitations

## Refresh without user validation

When both of the following settings are configured, non-interactive
reauthentication uses an internal token and does not resolve the username again:

```yaml
oauth2:
  refresh:
    enabled: true
    validate-user: false
```

The silent reauthentication path therefore has no SSO username for duplicate
handling. It accepts the reauthentication, but it does not check or renew the
username ownership record.

Duplicate ownership currently shares the in-memory storage expiry configured by
`oauth2.refresh.expires`, which defaults to eight hours. As a result, an active
client's ownership record can expire even when OpenVPN regularly performs silent
reauthentication. A later client using the same username may then be accepted
without terminating the earlier client.

Use `oauth2.refresh.validate-user=true` when duplicate username replacement must
continue to resolve the username during refresh. This setting makes refresh
requests depend on the OIDC provider and does not remove the process-local storage
limitations described below.

## Restarts and multiple instances

Username ownership is stored in memory by the local `openvpn-auth-oauth2`
process.

- An in-process SIGHUP configuration reload retains the map.
- A complete process or container restart creates an empty map.
- Separate `openvpn-auth-oauth2` processes do not share ownership information.
- A CID belongs to one OpenVPN server, so a process connected to another server
  cannot terminate that client with `client-kill`.

If OpenVPN preserves an established client while `openvpn-auth-oauth2` restarts,
the restarted process does not automatically reconstruct that client's username
ownership. The next login with the same username may therefore be accepted
without replacing the established client.

The setting provides single-session replacement only within one running
`openvpn-auth-oauth2` process and its directly connected OpenVPN server. It does
not provide deployment-wide single-session enforcement across replicas or
multiple OpenVPN servers.

## Authentication bypass

Clients accepted through `openvpn.bypass.common-names` skip SSO authentication.
They are accepted directly and are not added to the SSO username ownership map.
Consequently, this feature does not replace:

- another bypassed client with the same certificate common name; or
- a bypassed client whose common name happens to equal an authenticated user's
  resolved SSO username.

OpenVPN's own common-name behavior still applies to those clients. If
`duplicate-cn` is not configured, OpenVPN handles duplicate certificate common
names independently.

## Exact username matching

Usernames are compared as exact, case-sensitive strings. The application does not
trim whitespace, fold letter case, or normalize Unicode before creating the
duplicate ownership key. For example, these values are different usernames:

- `alice` and `Alice`;
- `alice` and `alice `;
- visually identical Unicode strings that use different normalization forms.

Configure `oauth2.openvpn-username` so it returns a stable, canonical identifier.
An immutable provider subject is less likely to change than a display name or
email address, but the selected claim must match the deployment's identity and
authorization requirements. Any normalization should happen consistently before
the username is used for duplicate detection, client configuration, logging, or
authorization.

The feature cannot track an authentication result that has no username. When the
resolved username is empty or intentionally omitted, the client is accepted
without duplicate username handling.
