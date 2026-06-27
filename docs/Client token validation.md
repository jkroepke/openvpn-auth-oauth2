# Client Token Validation with CEL

openvpn-auth-oauth2 supports advanced token validation using the [Common Expression Language (CEL)](https://github.com/google/cel-spec). CEL allows you to write custom validation rules to verify that the OAuth2 ID token claims match the OpenVPN user's context.

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
    expression: 'openVPNUserCommonName == oauth2TokenClaims.preferred_username'
```

### Environment Variable

```bash
CONFIG_OAUTH2_VALIDATE_EXPRESSION='openVPNUserCommonName == oauth2TokenClaims.preferred_username'
```

> [!IMPORTANT]
> CEL validation is performed **both during initial OAuth2 authentication and during token refresh**. This means your validation rules will be continuously enforced throughout the entire lifecycle of a VPN session. Make sure your expressions account for both scenarios using the `authMode` variable if needed.

## Available Variables

The following variables are available in your CEL expressions:

| Variable | Type | Description |
|----------|------|-------------|
| `authMode` | `string` | The authentication mode: `"interactive"` (initial OAuth2 login) or `"non-interactive"` (token refresh) |
| `openVPNSessionState` | `string` | The OpenVPN session state (e.g., `""`, `"Empty"`, `"Initial"`, `"Authenticated"`, `"Expired"`, `"Invalid"`, `"AuthenticatedEmptyUser"`, `"ExpiredEmptyUser"`) |
| `openVPNUserCommonName` | `string` | The common name (CN) of the OpenVPN client certificate |
| `openVPNUserIPAddr` | `string` | The IP address of the OpenVPN client |
| `oauth2TokenIPAddr` | `string` | The IP address claim from the OAuth2 ID token |
| `oauth2TokenClaims` | `map<string, dynamic>` | All claims from the OAuth2 ID token |

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
      has(oauth2TokenClaims.department) &&
      oauth2TokenClaims.department == 'engineering'
```

> [!IMPORTANT]
> If you try to access a claim that doesn't exist without using `has()`, the expression evaluation will fail, and the user will be denied access.

## Examples

### Basic Username Validation

Ensure the OpenVPN common name matches the OAuth2 username claim:

```yaml
oauth2:
  validate:
    expression: 'openVPNUserCommonName == oauth2TokenClaims.preferred_username'
```

### Email Domain Validation

Only allow users with email addresses from specific domains:

```yaml
oauth2:
  validate:
    expression: |
      has(oauth2TokenClaims.email) &&
      oauth2TokenClaims.email.endsWith('@example.com')
```

### Multiple Condition Validation

Combine multiple conditions with logical operators:

```yaml
oauth2:
  validate:
    expression: |
      openVPNUserCommonName == oauth2TokenClaims.preferred_username &&
      has(oauth2TokenClaims.email_verified) &&
      oauth2TokenClaims.email_verified == true
```

### Group-Based Validation

Allow access only if the user belongs to specific groups:

```yaml
oauth2:
  validate:
    expression: |
      has(oauth2TokenClaims.groups) &&
      ('vpn-users' in oauth2TokenClaims.groups || 'administrators' in oauth2TokenClaims.groups)
```

### IP Address Claim Validation

Validate that the VPN client IP matches the IP address claim from the token:

```yaml
oauth2:
  validate:
    expression: 'openVPNUserIPAddr == oauth2TokenIPAddr'
```

### Case-Insensitive Username Validation

Compare usernames in a case-insensitive manner using the `lowerAscii()` function:

```yaml
oauth2:
  validate:
    expression: |
      has(oauth2TokenClaims.preferred_username) && openVPNUserCommonName.lowerAscii() == string(oauth2TokenClaims.preferred_username).lowerAscii()
```

> [!IMPORTANT]
> When accessing claims from `oauth2TokenClaims` that you want to use with string functions, you may need to cast them to string using `string()` since claims are stored as dynamic types.

### Complex Custom Logic

Combine multiple conditions for sophisticated validation rules:

```yaml
oauth2:
  validate:
    expression: |
      openVPNUserCommonName == oauth2TokenClaims.sub &&
      (
        (has(oauth2TokenClaims.role) && oauth2TokenClaims.role == 'admin') ||
        (has(oauth2TokenClaims.vpn_access) && oauth2TokenClaims.vpn_access == true)
      ) &&
      (!has(oauth2TokenClaims.account_locked) || oauth2TokenClaims.account_locked == false)
```

### Email Prefix Validation

Extract and validate the prefix of an email address:

```yaml
oauth2:
  validate:
    expression: |
      has(oauth2TokenClaims.email) &&
      string(oauth2TokenClaims.email).split('@')[0] == openVPNUserCommonName
```

### Username Format Validation

Validate that a username contains only allowed characters using regular expression:

```yaml
oauth2:
  validate:
    expression: |
      has(oauth2TokenClaims.preferred_username) &&
      string(oauth2TokenClaims.preferred_username).matches('^[a-zA-Z0-9._-]+$')
```

### String Length Validation

Ensure usernames meet minimum length requirements:

```yaml
oauth2:
  validate:
    expression: |
      openVPNUserCommonName.size() >= 3 &&
      has(oauth2TokenClaims.preferred_username) &&
      string(oauth2TokenClaims.preferred_username).size() >= 3
```

### Domain-Based Routing

Allow different IP ranges based on email domain:

```yaml
oauth2:
  validate:
    expression: |
      has(oauth2TokenClaims.email) &&
      (
        (string(oauth2TokenClaims.email).endsWith('@internal.company.com') &&
         openVPNUserIPAddr.startsWith('10.0.')) ||
        (string(oauth2TokenClaims.email).endsWith('@company.com') &&
         openVPNUserIPAddr.startsWith('192.168.'))
      )
```

### Authentication Mode Based Validation

Apply different validation rules based on whether this is an initial login or a token refresh:

```yaml
oauth2:
  validate:
    expression: |
      authMode == 'interactive' ||
      (authMode == 'non-interactive' && has(oauth2TokenClaims.refresh_allowed) && oauth2TokenClaims.refresh_allowed == true)
```

### Session State Validation

Validate based on the current OpenVPN session state:

```yaml
oauth2:
  validate:
    expression: |
      openVPNSessionState in ['Initial', 'Authenticated', 'AuthenticatedEmptyUser'] &&
      openVPNUserCommonName == oauth2TokenClaims.preferred_username
```

### Combined Mode and State Validation

Combine authentication mode and session state for fine-grained control:

```yaml
oauth2:
  validate:
    expression: |
      (authMode == 'interactive' && openVPNSessionState == 'Initial') ||
      (authMode == 'non-interactive' && openVPNSessionState == 'Authenticated')
```
