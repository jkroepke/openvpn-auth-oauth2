# Client Token Validation with CEL

openvpn-auth-oauth2 supports identity validation using the [Common Expression Language (CEL)](https://github.com/google/cel-spec).
CEL rules can evaluate the normalized user, raw OAuth2 ID token claims, and the
OpenVPN session context.

## Overview

CEL validation provides a flexible way to enforce security policies by allowing you to write custom expressions that evaluate to `true` or `false`. This validation happens:

1. **During interactive authentication** - After the OAuth2 authentication flow completes but before the OpenVPN connection is established
2. **During token refresh** - When an existing OpenVPN session is refreshed using a refresh token (non-interactive authentication)

This ensures that access policies are continuously enforced throughout the lifecycle of the VPN connection, not just during initial authentication.

## Configuration

To enable CEL validation, configure the `oauth2.validate.expression` property in your configuration file:

### YAML Configuration

```yaml
oauth2:
  validate:
    expression: 'openvpn.commonName == user.username'
```

### Environment Variable

```bash
OPENVPN_AUTH_OAUTH2_OAUTH2_VALIDATE_EXPRESSION='openvpn.commonName == user.username'
```

> [!IMPORTANT]
> CEL validation is performed **both during initial OAuth2 authentication and during token refresh**. This means your validation rules will be continuously enforced throughout the entire lifecycle of a VPN session. Make sure your expressions account for both scenarios using `auth.mode` if needed.

## Available Variables

The following variables are available in your CEL expressions:

| Variable | Type | Description |
|----------|------|-------------|
| `auth.mode` | `string` | The authentication mode: `"interactive"` (initial OAuth2 login) or `"non-interactive"` (token refresh) |
| `openvpn.sessionState` | `string` | The OpenVPN session state (e.g., `""`, `"Empty"`, `"Initial"`, `"Authenticated"`, `"Expired"`, `"Invalid"`, `"AuthenticatedEmptyUser"`, `"ExpiredEmptyUser"`) |
| `openvpn.commonName` | `string` | The common name (CN) of the OpenVPN client certificate |
| `openvpn.ip` | `string` | The IP address of the OpenVPN client |
| `token.ip` | `string` | The IP address claim from the OAuth2 ID token |
| `token.claims` | `map<string, dynamic>` | All claims from the OAuth2 ID token |
| `user.subject` | `string` | The normalized provider subject |
| `user.email` | `string` | The normalized email address |
| `user.username` | `string` | The final username after `oauth2.openvpn-username` and common-name fallback |
| `user.groups` | `list<string>` | The normalized groups |
| `user.roles` | `list<string>` | The normalized roles |

Prefer `user.*` for rules that should work with generic OIDC, UserInfo, GitHub,
and refresh authentication. Use `token.claims.*` for provider-specific claims.
See [CEL Language Features](CEL%20Language%20Features.md) for the normalization
rules and the context shared by all CEL settings.

## Expression Requirements

- The CEL expression **must evaluate to a boolean** (`true` or `false`)
- If the expression evaluates to `true`, the user is granted access
- If the expression evaluates to `false`, the user is denied access
- If the expression evaluation fails (e.g., syntax error, accessing a non-existent claim), the user is denied access

## Safe Claim Access

Use the `has()` function to safely check for claim existence before accessing it:

```yaml
oauth2:
  validate:
    expression: |
      has(token.claims.department) &&
      token.claims.department == 'engineering'
```

> [!IMPORTANT]
> If you try to access a claim that doesn't exist without using `has()`, the expression evaluation will fail, and the user will be denied access.

## Examples

### Basic Username Validation

Ensure the OpenVPN common name matches the OAuth2 username claim:

```yaml
oauth2:
  validate:
    expression: 'openvpn.commonName == user.username'
```

### Email Domain Validation

Only allow users with email addresses from specific domains:

```yaml
oauth2:
  validate:
    expression: |
      user.email.endsWith('@example.com')
```

### Multiple Condition Validation

Combine multiple conditions with logical operators:

```yaml
oauth2:
  validate:
    expression: |
      openvpn.commonName == user.username &&
      has(token.claims.email_verified) &&
      token.claims.email_verified == true
```

### Group-Based Validation

Allow access only if the user belongs to specific groups:

```yaml
oauth2:
  validate:
    expression: |
      'vpn-users' in user.groups || 'administrators' in user.groups
```

### IP Address Claim Validation

Validate that the VPN client IP matches the IP address claim from the token:

```yaml
oauth2:
  validate:
    expression: 'openvpn.ip == token.ip'
```

### Case-Insensitive Username Validation

Compare usernames in a case-insensitive manner using the `lowerAscii()` function:

```yaml
oauth2:
  validate:
    expression: |
      openvpn.commonName.lowerAscii() == user.username.lowerAscii()
```

> [!IMPORTANT]
> When accessing claims from `token.claims` that you want to use with string functions, you may need to cast them to string using `string()` since claims are stored as dynamic types.

### Complex Custom Logic

Combine multiple conditions for sophisticated validation rules:

```yaml
oauth2:
  validate:
    expression: |
      openvpn.commonName == token.claims.sub &&
      (
        (has(token.claims.role) && token.claims.role == 'admin') ||
        (has(token.claims.vpn_access) && token.claims.vpn_access == true)
      ) &&
      (!has(token.claims.account_locked) || token.claims.account_locked == false)
```

### Email Prefix Validation

Extract and validate the prefix of an email address:

```yaml
oauth2:
  validate:
    expression: |
      user.email.split('@')[0] == openvpn.commonName
```

### Username Format Validation

Validate that a username contains only allowed characters using regular expression:

```yaml
oauth2:
  validate:
    expression: |
      user.username.matches('^[a-zA-Z0-9._-]+$')
```

### String Length Validation

Ensure usernames meet minimum length requirements:

```yaml
oauth2:
  validate:
    expression: |
      openvpn.commonName.size() >= 3 &&
      user.username.size() >= 3
```

### Domain-Based Routing

Allow different IP ranges based on email domain:

```yaml
oauth2:
  validate:
    expression: |
      (
        (user.email.endsWith('@internal.company.com') &&
         openvpn.ip.startsWith('10.0.')) ||
        (user.email.endsWith('@company.com') &&
         openvpn.ip.startsWith('192.168.'))
      )
```

### Authentication Mode Based Validation

Apply different validation rules based on whether this is an initial login or a token refresh:

```yaml
oauth2:
  validate:
    expression: |
      auth.mode == 'interactive' ||
      (auth.mode == 'non-interactive' && has(token.claims.refresh_allowed) && token.claims.refresh_allowed == true)
```

### Session State Validation

Validate based on the current OpenVPN session state:

```yaml
oauth2:
  validate:
    expression: |
      openvpn.sessionState in ['Initial', 'Authenticated', 'AuthenticatedEmptyUser'] &&
      openvpn.commonName == user.username
```

### Combined Mode and State Validation

Combine authentication mode and session state for fine-grained control:

```yaml
oauth2:
  validate:
    expression: |
      (auth.mode == 'interactive' && openvpn.sessionState == 'Initial') ||
      (auth.mode == 'non-interactive' && openvpn.sessionState == 'Authenticated')
```
