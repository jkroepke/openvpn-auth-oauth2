# OpenVPN Username

## Overview

This document covers various aspects of username handling in openvpn-auth-oauth2, including how to pass usernames from OAuth2 providers to OpenVPN, client-side authentication requirements, and configuration options.

## Client-Side Requirements

### Mandatory `auth-user-pass` Configuration

To use username functionality with openvpn-auth-oauth2, the OpenVPN client **must** have `auth-user-pass` configured. This is a mandatory requirement for the authentication flow to work properly.

**Important:** Although openvpn-auth-oauth2 theoretically doesn't require client-side authentication, the OpenVPN client expects it.

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

   Note: The username/password can be any dummy value as they won't be validated by openvpn-auth-oauth2 or OpenVPN itself during the OAuth2 flow.

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

**Important Note:** During authentication, it's expected that the common-name is not the value of the username. This may be misleading because after authentication, the common name has the correct value in OpenVPN logs.

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

#### Important Limitations

⚠️ **OpenVPN Client-Config-Dir Compatibility:**

When `openvpn.override-username` is enabled, OpenVPN's native `client-config-dir` functionality **will not work** because the username is set **after** client configs are read.

**Workaround:** Use openvpn-auth-oauth2's built-in [Client specific configuration](Client%20specific%20configuration.md) feature instead, which:
- Works seamlessly with `openvpn.override-username`
- Uses `openvpn.client-config.expression` to resolve configuration files from the normalized identity and raw token claims
- Can merge several configuration files or show a profile selector with `openvpn.client-config.strategy: user-selector`

For more details, see the OpenVPN man page regarding `override-username` limitations.

### Limiting a Username to One Active Session

OpenVPN checks duplicate common names before `override-username` replaces a
placeholder username with the identity resolved from OAuth2. As a result,
OpenVPN's common-name check cannot prevent two clients that use the same shared
profile from authenticating as the same OAuth2 user.

Enable `openvpn.enforce-unique-user` to replace active sessions based on the
resolved OAuth2 username. This applies the single-client behavior that OpenVPN
normally bases on a certificate common names, and that `duplicate-cn` disables,
to the resolved user identity:

```yaml
openvpn:
  override-username: true
  enforce-unique-user: true
```

The option requires OpenVPN 2.7 or later and a direct management-interface
connection. It is not compatible with the [OpenVPN Plugin](OpenVPN%20Plugin).
Configuration validation rejects the option unless `openvpn.override-username`
is also enabled.

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

`HALT` does not revoke an `auth-gen-token` on the server. It prevents the
displaced client from immediately reusing an in-memory token; a later manual
connection starts a new authentication flow.

The check applies to interactive authentication, silent reauthentication, and
non-interactive reconnects. When `oauth2.refresh.validate-user=false`, the
resolved username is retained in encrypted refresh state so these paths use the
same identity. The current CID is excluded, so a TLS reauthentication does not
terminate its own session.

This setting limits sessions on the OpenVPN server connected to this
openvpn-auth-oauth2 process. It does not coordinate sessions across separate
OpenVPN servers.

### Alternative: `openvpn.auth-token-user`

If you're using OpenVPN Server < 2.7 or cannot use `override-username`, the `openvpn.auth-token-user` option provides limited username support:

```bash
--openvpn.auth-token-user
```

This option uses the `auth-token-user` push command to send a base64-encoded username, but only when the client username is empty. This has more limitations compared to `override-username`.
