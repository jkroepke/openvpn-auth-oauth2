## CEL Language Features

[CEL, the Common Expression Language](https://cel.dev/), is a small expression language designed for
fast and safe evaluation of user-defined rules. openvpn-auth-oauth2 uses CEL for
configuration values that need logic, such as token validation, deriving the
OpenVPN username, and resolving client configuration names. CEL expressions can
inspect the variables provided by openvpn-auth-oauth2, call the documented
string and list helpers, and return the type required by the specific setting.
They cannot access files, make network calls, or execute arbitrary code.

CEL supports many standard operations:

### Comparison Operators
- `==` (equals)
- `!=` (not equals)
- `<`, `<=`, `>`, `>=` (numeric comparisons)

### Logical Operators
- `&&` (AND)
- `||` (OR)
- `!` (NOT)

### Available Variables

The available variables depend on the CEL expression being evaluated.

#### `oauth2.validate.expression`

- `authMode`: authentication mode, for example `interactive` or
  `non-interactive`
- `openVPNSessionState`: OpenVPN session state
- `openVPNUserCommonName`: common name of the OpenVPN user
- `openVPNUserIPAddr`: IP address of the OpenVPN user
- `oauth2TokenIPAddr`: IP address claim from the OAuth2 ID token
- `oauth2TokenClaims`: OAuth2 ID token claims

#### `oauth2.openvpn-username`

- `oauth2TokenClaims`: OAuth2 ID token claims

#### `openvpn.client-config.expression`

- `oauth2TokenClaims`: OAuth2 ID token claims
- `openVPNUserCommonName`: common name of the OpenVPN user
- `username`: resolved OpenVPN username after `oauth2.openvpn-username` has
  been evaluated

### Extension Libraries

All CEL expressions load the [CEL strings extension](https://pkg.go.dev/github.com/google/cel-go/ext#Strings)
and [CEL lists extension](https://pkg.go.dev/github.com/google/cel-go/ext#Lists).

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
- `in` - Check if an element is in a list
- `size()` - Get the size of a list or map
- `exists(var, predicate)` - Check if any element matches
  - Example: `oauth2TokenClaims.groups.exists(g, g == 'vpn-users')`
- `all(var, predicate)` - Check if every element matches
  - Example: `oauth2TokenClaims.groups.all(g, g.startsWith('vpn-'))`
- `exists_one(var, predicate)` - Check if exactly one element matches
  - Example: `oauth2TokenClaims.groups.exists_one(g, g == 'vpn-admin')`
- `filter(var, predicate)` - Keep matching elements
  - Example: `oauth2TokenClaims.groups.filter(g, g.startsWith('vpn-'))`
- `map(var, expression)` - Transform elements
  - Example: `oauth2TokenClaims.groups.map(g, g.lowerAscii())`
- `map(var, predicate, expression)` - Transform matching elements
  - Example: `oauth2TokenClaims.groups.map(g, g.startsWith('vpn-'), g.lowerAscii())`

The CEL lists extension adds more list helpers:

- `slice(<int>, <int>)` - Return a sub-list
  - Example: `['base', 'admin', 'net'].slice(0, 2)` returns `['base', 'admin']`
- `flatten()` - Flatten one nested list level
  - Example: `[['base'], ['admin', 'net']].flatten()` returns `['base', 'admin', 'net']`
- `flatten(<int>)` - Flatten a specific number of nested list levels
- `sort()` - Sort a list of comparable values
  - Example: `['net', 'base', 'admin'].sort()` returns `['admin', 'base', 'net']`
- `sortBy(var, expression)` - Sort a list by a derived key
  - Example: `[{'name': 'admin', 'order': 2}, {'name': 'base', 'order': 1}].sortBy(p, p.order).map(p, p.name)`
- `reverse()` - Reverse list order
  - Example: `['base', 'admin'].reverse()` returns `['admin', 'base']`
- `distinct()` - Remove duplicate list elements while keeping first occurrence
  - Example: `['base', 'admin', 'base'].distinct()` returns `['base', 'admin']`

Example for client configuration:

```yaml
openvpn:
  client-config:
    expression: |
      (
        ['base'] +
        oauth2TokenClaims.groups
          .filter(g, g.startsWith('vpn-'))
          .map(g, g.replace('vpn-', ''))
          .sort() +
        [username]
      ).distinct()
```

Example that maps each group to one or more shared config files:

```yaml
openvpn:
  client-config:
    expression: |
      oauth2TokenClaims.groups
        .map(g, {
          'GRP-VPN': ['base-vpn'],
          'GRP-ADMIN': ['base-vpn', 'admin-routes'],
          'GRP-NETWORK': ['base-vpn', 'network-routes']
        }[g])
        .flatten()
        .distinct()
```

### Map/Object Functions
- `has()` - Check if a key exists in a map

### Type Conversion
- `string()` - Convert value to string (useful for casting claim values)

For more details, see:
- [CEL Specification](https://github.com/google/cel-spec/blob/master/doc/langdef.md)
- [CEL Strings Extension](https://github.com/google/cel-spec/blob/master/doc/extensions/strings.md)
- [cel-go Strings Documentation](https://pkg.go.dev/github.com/google/cel-go/ext#Strings)
- [cel-go Lists Documentation](https://pkg.go.dev/github.com/google/cel-go/ext#Lists)

## Error Handling

### Missing Claims

If you try to access a claim that doesn't exist in the ID token without checking first, the validation will fail:

```yaml
---
# ❌ Bad - will fail if 'department' claim doesn't exist
expression: 'oauth2TokenClaims.department == "engineering"'
---
# ✅ Good - safely checks for claim existence first
expression: 'has(oauth2TokenClaims.department) && oauth2TokenClaims.department == "engineering"'
```

### Invalid Expressions

If your CEL expression has syntax errors, openvpn-auth-oauth2 will fail to start and log an error message indicating the compilation failure.

### Non-Boolean Results

The expression must evaluate to a boolean. If it evaluates to another type (string, number, etc.), the validation will fail:

```yaml
# ❌ Bad - evaluates to a string, not a boolean
expression: 'openVPNUserCommonName'
---
# ✅ Good - evaluates to a boolean
expression: 'openVPNUserCommonName != ""'
```

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
