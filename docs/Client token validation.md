# Client Token Validation with CEL

openvpn-auth-oauth2 supports advanced token validation using the [Common Expression Language (CEL)](https://github.com/google/cel-spec). CEL allows you to write custom validation rules to verify that the OAuth2 ID token claims match the OpenVPN user's context.

## Overview

CEL validation provides a flexible way to enforce security policies by allowing you to write custom expressions that evaluate to `true` or `false`. This validation happens:

1. **During interactive authentication** - After the OAuth2 authentication flow completes but before the OpenVPN connection is established
2. **During token refresh** - When an existing OpenVPN session is refreshed using a refresh token (non-interactive authentication)

This ensures that access policies are continuously enforced throughout the lifecycle of the VPN connection, not just during initial authentication.

## Configuration

To enable CEL validation, configure the `oauth2.validate.cel` property in your configuration file:

### YAML Configuration

```yaml
oauth2:
  validate:
    cel: 'openVPNUserCommonName == oauth2TokenClaims.preferred_username'
```

### Environment Variable

```bash
CONFIG_OAUTH2_VALIDATE_VALIDATION__CEL='openVPNUserCommonName == oauth2TokenClaims.preferred_username'
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
    cel: |
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
    cel: 'openVPNUserCommonName == oauth2TokenClaims.preferred_username'
```

### Email Domain Validation

Only allow users with email addresses from specific domains:

```yaml
oauth2:
  validate:
    cel: |
      has(oauth2TokenClaims.email) &&
      oauth2TokenClaims.email.endsWith('@example.com')
```

### Multiple Condition Validation

Combine multiple conditions with logical operators:

```yaml
oauth2:
  validate:
    cel: |
      openVPNUserCommonName == oauth2TokenClaims.preferred_username &&
      has(oauth2TokenClaims.email_verified) &&
      oauth2TokenClaims.email_verified == true
```

### Group-Based Validation

Allow access only if the user belongs to specific groups:

```yaml
oauth2:
  validate:
    cel: |
      has(oauth2TokenClaims.groups) &&
      ('vpn-users' in oauth2TokenClaims.groups || 'administrators' in oauth2TokenClaims.groups)
```

### IP Address Range Validation

Validate that the VPN client IP is in an expected range:

```yaml
oauth2:
  validate:
    cel: 'openVPNUserIPAddr.startsWith("10.0.") || openVPNUserIPAddr.startsWith("192.168.")'
```

### Case-Insensitive Username Validation

Compare usernames in a case-insensitive manner using the `lowerAscii()` function:

```yaml
oauth2:
  validate:
    cel: |
      has(oauth2TokenClaims.preferred_username) && openVPNUserCommonName.lowerAscii() == string(oauth2TokenClaims.preferred_username).lowerAscii()
```

> [!IMPORTANT]
> When accessing claims from `oauth2TokenClaims` that you want to use with string functions, you may need to cast them to string using `string()` since claims are stored as dynamic types.

### Complex Custom Logic

Combine multiple conditions for sophisticated validation rules:

```yaml
oauth2:
  validate:
    cel: |
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
    cel: |
      has(oauth2TokenClaims.email) &&
      string(oauth2TokenClaims.email).split('@')[0] == openVPNUserCommonName
```

### Username Format Validation

Validate that a username contains only allowed characters using regular expression:

```yaml
oauth2:
  validate:
    cel: |
      has(oauth2TokenClaims.preferred_username) &&
      string(oauth2TokenClaims.preferred_username).matches('^[a-zA-Z0-9._-]+$')
```

### String Length Validation

Ensure usernames meet minimum length requirements:

```yaml
oauth2:
  validate:
    cel: |
      openVPNUserCommonName.size() >= 3 &&
      has(oauth2TokenClaims.preferred_username) &&
      string(oauth2TokenClaims.preferred_username).size() >= 3
```

### Domain-Based Routing

Allow different IP ranges based on email domain:

```yaml
oauth2:
  validate:
    cel: |
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
    cel: |
      authMode == 'interactive' ||
      (authMode == 'non-interactive' && has(oauth2TokenClaims.refresh_allowed) && oauth2TokenClaims.refresh_allowed == true)
```

### Session State Validation

Validate based on the current OpenVPN session state:

```yaml
oauth2:
  validate:
    cel: |
      openVPNSessionState in ['Initial', 'Authenticated', 'AuthenticatedEmptyUser'] &&
      openVPNUserCommonName == oauth2TokenClaims.preferred_username
```

### Combined Mode and State Validation

Combine authentication mode and session state for fine-grained control:

```yaml
oauth2:
  validate:
    cel: |
      (authMode == 'interactive' && openVPNSessionState == 'Initial') ||
      (authMode == 'non-interactive' && openVPNSessionState == 'Authenticated')
```

## CEL Language Features

CEL supports many standard operations:

### Comparison Operators
- `==` (equals)
- `!=` (not equals)
- `<`, `<=`, `>`, `>=` (numeric comparisons)

### Logical Operators
- `&&` (AND)
- `||` (OR)
- `!` (NOT)

### String Functions

The following string functions are available through the [CEL strings extension](https://pkg.go.dev/github.com/google/cel-go/ext#Strings):

#### Basic String Operations
- `startsWith(<string>)` - Check if string starts with prefix
- `endsWith(<string>)` - Check if string ends with suffix
- `contains(<string>)` - Check if string contains substring
- `matches(<string>)` - Check if string matches a regular expression pattern

#### Case Conversion
- `lowerAscii()` - Convert ASCII characters to lowercase
  - Example: `'TacoCat'.lowerAscii()` returns `'tacocat'`
- `upperAscii()` - Convert ASCII characters to uppercase
  - Example: `'TacoCat'.upperAscii()` returns `'TACOCAT'`

#### String Searching
- `indexOf(<string>)` - Returns the index of the first occurrence of a substring (or -1 if not found)
  - Example: `'hello mellow'.indexOf('ello')` returns `1`
- `indexOf(<string>, <int>)` - Search starting from a specific position
  - Example: `'hello mellow'.indexOf('ello', 2)` returns `7`
- `lastIndexOf(<string>)` - Returns the index of the last occurrence of a substring
  - Example: `'hello mellow'.lastIndexOf('ello')` returns `7`
- `lastIndexOf(<string>, <int>)` - Search up to a specific position

#### String Manipulation
- `substring(<int>)` - Extract substring from position to end
  - Example: `'tacocat'.substring(4)` returns `'cat'`
- `substring(<int>, <int>)` - Extract substring from start (inclusive) to end (exclusive)
  - Example: `'tacocat'.substring(0, 4)` returns `'taco'`
- `trim()` - Remove leading and trailing whitespace
  - Example: `'  \ttrim\n    '.trim()` returns `'trim'`
- `replace(<string>, <string>)` - Replace all occurrences of a substring
  - Example: `'hello hello'.replace('he', 'we')` returns `'wello wello'`
- `replace(<string>, <string>, <int>)` - Replace with a limit on number of replacements
  - Example: `'hello hello'.replace('he', 'we', 1)` returns `'wello hello'`
- `reverse()` - Reverse the string
  - Example: `'gums'.reverse()` returns `'smug'`

#### String Splitting and Joining
- `split(<string>)` - Split string by separator into a list
  - Example: `'hello hello hello'.split(' ')` returns `['hello', 'hello', 'hello']`
- `split(<string>, <int>)` - Split with a limit on number of substrings
  - Example: `'hello hello hello'.split(' ', 2)` returns `['hello', 'hello hello']`
- `join()` - Join list of strings (on a list, not a string)
  - Example: `['hello', 'mellow'].join()` returns `'hellomellow'`
- `join(<string>)` - Join list of strings with separator
  - Example: `['hello', 'mellow'].join(' ')` returns `'hello mellow'`

#### String Formatting
- `format(<list>)` - Format string with printf-style substitutions
  - Supports: `%s` (string), `%d` (integer), `%f` (float), `%e` (scientific), `%b` (binary), `%x`/`%X` (hex), `%o` (octal)
  - Example: `"Hello %s, you have %d messages".format(['Alice', 5])` returns `'Hello Alice, you have 5 messages'`

#### String Utilities
- `strings.quote(<string>)` - Make string safe to print by escaping special characters
  - Example: `strings.quote('single-quote with "double quote"')` returns `'"single-quote with \"double quote\""'`

### List Functions
- `in` - Check if element is in list
- `size()` - Get the size of a list or map

### Map/Object Functions
- `has()` - Check if a key exists in a map

### Type Conversion
- `string()` - Convert value to string (useful for casting claim values)

For more details, see:
- [CEL Specification](https://github.com/google/cel-spec/blob/master/doc/langdef.md)
- [CEL Strings Extension](https://github.com/google/cel-spec/blob/master/doc/extensions/strings.md)
- [cel-go Strings Documentation](https://pkg.go.dev/github.com/google/cel-go/ext#Strings)

## Error Handling

### Missing Claims

If you try to access a claim that doesn't exist in the ID token without checking first, the validation will fail:

```yaml
---
# ❌ Bad - will fail if 'department' claim doesn't exist
cel: 'oauth2TokenClaims.department == "engineering"'
---
# ✅ Good - safely checks for claim existence first
cel: 'has(oauth2TokenClaims.department) && oauth2TokenClaims.department == "engineering"'
```

### Invalid Expressions

If your CEL expression has syntax errors, openvpn-auth-oauth2 will fail to start and log an error message indicating the compilation failure.

### Non-Boolean Results

The expression must evaluate to a boolean. If it evaluates to another type (string, number, etc.), the validation will fail:

```yaml
# ❌ Bad - evaluates to a string, not a boolean
cel: 'openVPNUserCommonName'
---
# ✅ Good - evaluates to a boolean
cel: 'openVPNUserCommonName != ""'
```

## Relationship with Other Validation Options

CEL validation is **in addition to** the existing validation options. All validation checks must pass for the user to be granted access:

1. Standard validation checks (`oauth2.validate.common-name`, `oauth2.validate.groups`, etc.)
2. CEL validation (if configured)
3. Provider-specific validation

If any validation step fails, the user is denied access.

## Best Practices

1. **Always use `has()` to check for optional claims** before accessing them to avoid validation failures
2. **Keep expressions simple and readable** - complex logic can be hard to debug
3. **Test your CEL expressions** with different token scenarios during development
4. **Log validation failures** to help troubleshoot issues
5. **Document your validation rules** in comments or documentation for team members.

## Security Considerations

- CEL validation happens **after** OAuth2 authentication, so users must authenticate successfully before CEL rules are applied
- CEL expressions cannot access external resources or make network calls - they can only evaluate the provided variables
- CEL is sandboxed and safe - expressions cannot execute arbitrary code or affect the system
- Combining CEL with other validation options (groups, roles, common name) provides defense-in-depth

## Debugging

If validation fails, check the openvpn-auth-oauth2 logs for error messages. The logs will indicate:
- CEL compilation errors (if the expression syntax is invalid)
- Evaluation errors (if the expression fails during evaluation)
- Which specific validation check failed

Example log messages:
```
failed to evaluate CEL expression: no such key: unknown
CEL validation failed
CEL expression did not evaluate to a boolean value
```

## Performance

CEL expressions are compiled once at a startup and then evaluated efficiently for each authentication request. The performance impact is minimal, even for complex expressions.
