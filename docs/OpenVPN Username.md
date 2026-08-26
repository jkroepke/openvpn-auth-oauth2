# OpenVPN Username

## Overview

This document covers various aspects of username handling in openvpn-auth-oauth2, including how to pass usernames from OAuth2 providers to OpenVPN, client-side authentication requirements, and configuration options.

## Client-Side Requirements

### Mandatory `auth-user-pass` Configuration

To use username functionality with openvpn-auth-oauth2, the OpenVPN client **must** have `auth-user-pass` configured. This is a mandatory requirement for the authentication flow to work properly.

> [!IMPORTANT]
> Although openvpn-auth-oauth2 does not validate a client-side password, the
> OpenVPN client expects `auth-user-pass` for this authentication flow.

You have two options:

1. **Interactive Mode**: Use `auth-user-pass` without credentials, prompting the user for input:
   ```
   auth-user-pass
   ```

2. **Inline Mode**: Define dummy credentials inline to prevent prompting (recommended for SSO-only authentication):
   ```
   <auth-user-pass>
   username
   password
   </auth-user-pass>
   ```

The inline username and password can contain placeholder values. Neither
openvpn-auth-oauth2 nor OpenVPN validates them during the OAuth2 flow.

**Upstream Issue:** [`OpenVPN/openvpn` #501](https://github.com/OpenVPN/openvpn/issues/501) (Please react with :+1: if you're affected.)

### Error: "No client-side authentication method is specified"

If you encounter this error, ensure that `auth-user-pass` is configured in your client configuration as described above.

## Using `username-as-common-name` on OpenVPN Server

When setting up `username-as-common-name` on the OpenVPN server, you **must** also configure `openvpn.common-name.environment-variable-name` to `username`:

```bash
--openvpn.common-name.environment-variable-name=username
```

Or via environment variable:

```dotenv
OPENVPN_AUTH_OAUTH2_OPENVPN_COMMON_NAME_ENVIRONMENT_VARIABLE_NAME=username
```

### Why This Configuration Is Required

This configuration is essential because `username-as-common-name` functions **post-authentication**. By aligning the environment variable name with `username`, you ensure smooth operation.

> [!NOTE]
> During authentication, the common name does not yet contain the username.
> OpenVPN updates it after authentication, so later log entries show the
> expected value.

**Upstream Issue:** [`OpenVPN/openvpn` #498](https://github.com/OpenVPN/openvpn/issues/498#issuecomment-1939194149)

## Passing Usernames from OAuth2 Provider to OpenVPN

### Default Behavior

By default, openvpn-auth-oauth2 does not pass the username from the OAuth2 provider to OpenVPN. This limitation is due to OpenVPN's authentication interface design, which does not provide a native mechanism to set the username post-authentication.

**Limitation:** The IP persistence file or statistics in OpenVPN may contain empty usernames when using the default configuration.

**Upstream Issue:** For native OpenVPN support, please up-vote the feature request on GitHub: [`OpenVPN/openvpn` #299](https://github.com/OpenVPN/openvpn/issues/299)

### Using `openvpn.override-username` (Recommended)

**Requires OpenVPN Server 2.7+**

The `openvpn.override-username` configuration option passes the username from
the normalized OAuth2 identity to OpenVPN using the `override-username` command.
This allows real usernames to appear in OpenVPN statistics and logs.

#### Configuration

Enable this feature using:

```bash
--openvpn.override-username
```

Or via environment variable:

```bash
OPENVPN_AUTH_OAUTH2_OPENVPN_OVERRIDE_USERNAME=true
```

#### Username source

The username is resolved from the normalized identity using
`oauth2.openvpn-username`. The value is a CEL expression that must evaluate to
a string.

By default, the expression is `user.username`. Before this expression runs,
`user.username` contains the provider's username candidate:

- the `preferred_username` value from UserInfo or an OIDC ID token;
- the GitHub login for the GitHub provider.

The same expression is applied during interactive authentication, UserInfo
authentication, and refresh validation. If the setting is empty, or if the
expression returns an empty string, the OpenVPN common name is used.

Example configurations:

```bash
# Use the normalized email address
--oauth2.openvpn-username='user.email'

# Use a provider-specific raw claim
--oauth2.openvpn-username='string(token.claims.employee_id)'

# Transform normalized identity data
--oauth2.openvpn-username='user.email.split("@")[0]'
```

The complete `auth`, `openvpn`, `token`, and `user` context is available. For
more details, see [CEL Language Features](CEL%20Language%20Features.md).

#### Important limitations

> [!WARNING]
> When `openvpn.override-username` is enabled, OpenVPN's native
> `client-config-dir` does not use the resolved OIDC username because the
> username is replaced after OpenVPN reads its client configuration.

Use openvpn-auth-oauth2's built-in
[Client-specific configuration](Client%20specific%20configuration.md) instead.
It:

- works with `openvpn.override-username`;
- uses `openvpn.client-config.expression` to resolve configuration files from
  the normalized identity and raw token claims; and
- can merge several configuration files or show a profile selector with
  `openvpn.client-config.strategy: user-selector`.

For more details, see the OpenVPN man page regarding `override-username` limitations.

### Limiting a Username to One Active Session

Enable `openvpn.enforce-unique-user` to replace active sessions based on the
value resolved by `oauth2.openvpn-username`. Before accepting a client,
openvpn-auth-oauth2 compares that value with the exact `Username` field in
OpenVPN's `status 3` output.

> [!IMPORTANT]
> This setting always requires a direct OpenVPN management-interface
> connection. It is not compatible with the stable
> [OpenVPN Plugin](OpenVPN%20Plugin), because the plugin does not expose the
> `status 3` and `client-kill` commands used by this check.

#### Enforce an existing OpenVPN username or common name

This mode does not require OpenVPN 2.7 or `openvpn.override-username`. The value
resolved by `oauth2.openvpn-username` must already match the `Username` field
reported by OpenVPN. For example, an administrator can use the OpenVPN common
name as the resolved username and require it to match a trusted OIDC subject:

```yaml
oauth2:
  openvpn-username: openvpn.commonName
  validate:
    expression: openvpn.commonName.lowerAscii() == user.subject.lowerAscii()

openvpn:
  enforce-unique-user: true
```

> [!WARNING]
> Do not trust a client-controlled common name by itself. Bind it to a trusted
> OIDC subject or claim with `oauth2.validate.expression`, and ensure the same
> value appears in OpenVPN's `Username` status field. The correct expression
> depends on the identity provider and OpenVPN configuration.

When using OpenVPN's `username-as-common-name`, also set
`openvpn.common-name.environment-variable-name: username` as described in
[Using `username-as-common-name` on OpenVPN Server](#using-username-as-common-name-on-openvpn-server).
See [issue #1117](https://github.com/jkroepke/openvpn-auth-oauth2/issues/1117)
for the background to this mode.

#### Enforce the resolved OIDC username

When OpenVPN's existing username is a placeholder or several clients share a
profile, use `openvpn.override-username` to write the resolved OIDC username to
OpenVPN. This mode requires OpenVPN 2.7 or later:

```yaml
openvpn:
  override-username: true
  enforce-unique-user: true
```

OpenVPN checks duplicate common names before `override-username` replaces the
username. Consequently, OpenVPN's native common-name check alone cannot prevent
two clients using the same shared profile from authenticating as the same OIDC
user.

Before accepting a client, openvpn-auth-oauth2 requests `status 3`, finds every
active client with an exactly matching `Username` field, and sends
`client-kill <CID> HALT` for each match except the CID currently
authenticating. `HALT` tells the displaced client to clear cached
authentication and exit instead of automatically reconnecting with a cached
authentication token. The status lookup and client acceptance are serialized
so two concurrent logins cannot both pass the check. A status, parsing, or kill
error prevents the new client from being accepted. If a matching CID
disconnected after the status lookup, authentication continues because the old
session is already gone.

> [!NOTE]
> `HALT` does not revoke an `auth-gen-token` on the server. It prevents the
> displaced client from immediately reusing an in-memory token; a later manual
> connection starts a new authentication flow.

The check applies to interactive authentication, silent reauthentication, and
non-interactive reconnects. When `oauth2.refresh.validate-user=false`, the
resolved username is retained in encrypted refresh state so these paths use the
same identity. The current CID is excluded, so a TLS reauthentication does not
terminate its own session.

> [!NOTE]
> This setting limits sessions only on the OpenVPN server connected to this
> `openvpn-auth-oauth2` process. It does not coordinate sessions across
> separate OpenVPN servers.

### Alternative: `openvpn.auth-token-user`

If you're using OpenVPN Server < 2.7 or cannot use `override-username`, the `openvpn.auth-token-user` option provides limited username support:

```bash
--openvpn.auth-token-user
```

This option uses the `auth-token-user` push command to send a base64-encoded username, but only when the client username is empty. This has more limitations compared to `override-username`.
