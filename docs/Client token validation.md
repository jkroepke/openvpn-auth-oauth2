# Client Token Validation with CEL

openvpn-auth-oauth2 supports advanced token validation using the [Common Expression Language (CEL)](https://github.com/google/cel-spec). CEL allows you to write custom validation rules to verify that the OAuth2 ID token claims match the OpenVPN user's context.

## Overview

CEL validation provides a flexible way to enforce security policies by allowing you to write custom expressions that evaluate to `true` or `false`. This validation happens after the OAuth2 authentication flow completes but before the OpenVPN connection is established.

## Configuration

To enable CEL validation, configure the `oauth2.validate.validation-cel` property in your configuration file:

### YAML Configuration

```yaml
oauth2:
  validate:
    validation-cel: 'openvpnUserCommonName == oauth2TokenClaims.preferred_username'
```

### Environment Variable

```bash
CONFIG_OAUTH2_VALIDATE_VALIDATION__CEL='openvpnUserCommonName == oauth2TokenClaims.preferred_username'
```

## Available Variables

The following variables are available in your CEL expressions:

| Variable | Type | Description |
|----------|------|-------------|
| `openvpnUserCommonName` | `string` | The common name (CN) of the OpenVPN client certificate |
| `openvpnUserIPAddr` | `string` | The IP address of the OpenVPN client |
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
    validation-cel: |
      has(oauth2TokenClaims.department) &&
      oauth2TokenClaims.department == 'engineering'
```

**Important:** If you try to access a claim that doesn't exist without using `has()`, the expression evaluation will fail and the user will be denied access.

## Examples

### Basic Username Validation

Ensure the OpenVPN common name matches the OAuth2 username claim:

```yaml
oauth2:
  validate:
    validation-cel: 'openvpnUserCommonName == oauth2TokenClaims.preferred_username'
```

### Email Domain Validation

Only allow users with email addresses from specific domains:

```yaml
oauth2:
  validate:
    validation-cel: |
      has(oauth2TokenClaims.email) &&
      oauth2TokenClaims.email.endsWith('@example.com')
```

### Multiple Condition Validation

Combine multiple conditions with logical operators:

```yaml
oauth2:
  validate:
    validation-cel: |
      openvpnUserCommonName == oauth2TokenClaims.preferred_username &&
      has(oauth2TokenClaims.email_verified) &&
      oauth2TokenClaims.email_verified == true
```

### Group-Based Validation

Allow access only if the user belongs to specific groups:

```yaml
oauth2:
  validate:
    validation-cel: |
      has(oauth2TokenClaims.groups) &&
      ('vpn-users' in oauth2TokenClaims.groups || 'administrators' in oauth2TokenClaims.groups)
```

### IP Address Range Validation

Validate that the VPN client IP is in an expected range:

```yaml
oauth2:
  validate:
    validation-cel: 'openvpnUserIPAddr.startsWith("10.0.") || openvpnUserIPAddr.startsWith("192.168.")'
```


### Complex Custom Logic

Combine multiple conditions for sophisticated validation rules:

```yaml
oauth2:
  validate:
    validation-cel: |
      openvpnUserCommonName == oauth2TokenClaims.sub &&
      (
        (has(oauth2TokenClaims.role) && oauth2TokenClaims.role == 'admin') ||
        (has(oauth2TokenClaims.vpn_access) && oauth2TokenClaims.vpn_access == true)
      ) &&
      (!has(oauth2TokenClaims.account_locked) || oauth2TokenClaims.account_locked == false)
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
- `startsWith()` - Check if string starts with prefix
- `endsWith()` - Check if string ends with suffix
- `contains()` - Check if string contains substring
- `matches()` - Check if string matches a regex pattern

### List Functions
- `in` - Check if element is in list
- `size()` - Get the size of a list or map

### Map/Object Functions
- `has()` - Check if a key exists in a map

For more details, see the [CEL specification](https://github.com/google/cel-spec/blob/master/doc/langdef.md).

## Error Handling

### Missing Claims

If you try to access a claim that doesn't exist in the ID token without checking first, the validation will fail:

```yaml
---
# ❌ Bad - will fail if 'department' claim doesn't exist
validation-cel: 'oauth2TokenClaims.department == "engineering"'
---
# ✅ Good - safely checks for claim existence first
validation-cel: 'has(oauth2TokenClaims.department) && oauth2TokenClaims.department == "engineering"'
```

### Invalid Expressions

If your CEL expression has syntax errors, openvpn-auth-oauth2 will fail to start and log an error message indicating the compilation failure.

### Non-Boolean Results

The expression must evaluate to a boolean. If it evaluates to another type (string, number, etc.), the validation will fail:

```yaml
# ❌ Bad - evaluates to a string, not a boolean
validation-cel: 'openvpnUserCommonName'
---
# ✅ Good - evaluates to a boolean
validation-cel: 'openvpnUserCommonName != ""'
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
5. **Document your validation rules** in comments or documentation for team members

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
