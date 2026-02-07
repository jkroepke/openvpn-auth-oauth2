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
CONFIG_OPENVPN_COMMON__NAME_ENVIRONMENT__VARIABLE__NAME=username
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

The `openvpn.override-username` configuration option enables passing the username from OAuth2 token claims to OpenVPN using the `override-username` command. This allows real usernames to appear in OpenVPN statistics and logs.

#### Configuration

Enable this feature using:

```bash
--openvpn.override-username
```

Or via environment variable:

```bash
CONFIG_OPENVPN_OVERRIDE__USERNAME=true
```

#### Username Source

The username is extracted from the OAuth2 ID token using one of these configurations (in order of precedence):

1. **`oauth2.openvpn-username-claim`** - Extract username from a specific token claim (default: `preferred_username`)
2. **`oauth2.openvpn-username-cel`** - Use a CEL expression to extract or transform the username from token claims

Example configurations:

```bash
# Use a specific claim
--oauth2.openvpn-username-claim=email

# Use CEL expression for complex transformations
--oauth2.openvpn-username-cel='oauth2TokenClaims.email.split("@")[0]'
```

For more details on CEL expressions, see the [Client token values](Client%20token%20validation.md#cel-language-features) documentation.

#### Important Limitations

⚠️ **OpenVPN Client-Config-Dir Compatibility:**

When `openvpn.override-username` is enabled, OpenVPN's native `client-config-dir` functionality **will not work** because the username is set **after** client configs are read.

**Workaround:** Use openvpn-auth-oauth2's built-in [Client specific configuration](Client%20specific%20configuration.md) feature instead, which:
- Works seamlessly with `openvpn.override-username`
- Uses token claims to lookup configuration files
- Provides additional features like profile selection UI

For more details, see the OpenVPN man page regarding `override-username` limitations.

### Alternative: `openvpn.auth-token-user`

If you're using OpenVPN Server < 2.7 or cannot use `override-username`, the `openvpn.auth-token-user` option provides limited username support:

```bash
--openvpn.auth-token-user
```

This option uses the `auth-token-user` push command to send a base64-encoded username, but only when the client username is empty. This has more limitations compared to `override-username`.
