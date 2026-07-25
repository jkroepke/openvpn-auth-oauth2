# Upgrade V2

Version 2 includes configuration changes for username resolution, client-specific
configuration, token validation, and security hardening.

## Environment variable prefix

Version 2 uses the project-specific `OPENVPN_AUTH_OAUTH2_` prefix for
environment variables. The previous `CONFIG_` prefix is no longer supported.
Rename every environment variable before upgrading:

| Version 1 | Version 2 |
| --- | --- |
| `CONFIG_FILE` | `OPENVPN_AUTH_OAUTH2_CONFIG_FILE` |
| `CONFIG_HTTP_LISTEN` | `OPENVPN_AUTH_OAUTH2_HTTP_LISTEN` |
| `CONFIG_OAUTH2_CLIENT_ID` | `OPENVPN_AUTH_OAUTH2_OAUTH2_CLIENT_ID` |
| `CONFIG_OPENVPN_PASS__THROUGH_ENABLED` | `OPENVPN_AUTH_OAUTH2_OPENVPN_PASS_THROUGH_ENABLED` |

The suffix conversion also changes: dots and dashes both become single
underscores. Rename existing `OPENVPN_AUTH_OAUTH2_` variables that contain
double underscores.

## Strict configuration parsing

Version 2 rejects invalid configuration input instead of silently using a
default:

- Boolean environment values must be exactly `true` or `false`.
- Malformed environment values, such as an invalid duration, stop startup with
  an error.
- Unknown variables with the `OPENVPN_AUTH_OAUTH2_` prefix stop startup with an
  error.
- Positional command-line arguments are rejected.

The unused top-level YAML `config:` property has been removed. Select the
configuration file with `--config` or `OPENVPN_AUTH_OAUTH2_CONFIG_FILE`.

Configuration precedence remains, from lowest to highest priority: built-in
defaults, YAML, environment variables, and command-line flags.

`openvpn.command-timeout` is now a public option for the maximum time to wait
for an OpenVPN management command response. Its default is `10s`. It can be
configured through YAML, the `--openvpn.command-timeout` flag, or
`OPENVPN_AUTH_OAUTH2_OPENVPN_COMMAND_TIMEOUT`.

## Security hardening

Review the rest of this page even if these hardening items do not apply to your
deployment. This section only requires action when you use reverse proxy headers
or the OpenVPN plugin.

### Reverse proxy headers

If `http.enable-proxy-headers` is enabled, `http.trusted-proxies` is now
required. openvpn-auth-oauth2 will reject the configuration if proxy headers are
enabled without at least one trusted proxy CIDR.

Use the CIDR ranges of the reverse proxies that connect directly to
openvpn-auth-oauth2:

```yaml
http:
  enable-proxy-headers: true
  trusted-proxies:
    - 127.0.0.1/32
    - 10.0.0.0/24
```

Environment variable configuration:

```ini
OPENVPN_AUTH_OAUTH2_HTTP_ENABLE_PROXY_HEADERS=true
OPENVPN_AUTH_OAUTH2_HTTP_TRUSTED_PROXIES=127.0.0.1/32,10.0.0.0/24
```

If openvpn-auth-oauth2 is not behind a reverse proxy, keep
`http.enable-proxy-headers` disabled.

### OpenVPN plugin

The OpenVPN plugin is no longer experimental.

The plugin management socket now requires password authentication. Existing
OpenVPN plugin configurations that pass only the listen socket must add a
password file argument, and openvpn-auth-oauth2 must use the same password for
`openvpn.password`.

Before:

```openvpn
plugin /path/to/openvpn-auth-oauth2.so "unix:///var/run/openvpn-oauth2.sock"
```

After:

```openvpn
plugin /path/to/openvpn-auth-oauth2.so "unix:///var/run/openvpn-oauth2.sock" "/etc/openvpn/oauth2-plugin-password.txt"
```

openvpn-auth-oauth2 configuration:

```yaml
openvpn:
  addr: unix:///var/run/openvpn-oauth2.sock
  password: "file:///etc/openvpn-auth-oauth2/oauth2-plugin-password.txt"
```

The two password files must contain the same password. They can be separate
files so OpenVPN and openvpn-auth-oauth2 can each read a file from the path
allowed by their service permissions.

## CEL context

Version 2 uses one namespaced context for username resolution, validation, and
client config resolution. Update every CEL expression to use the new names:

| Previous field | Version 2 field |
| --- | --- |
| `authMode` | `auth.mode` |
| `openVPNSessionState` | `openvpn.sessionState` |
| `openVPNUserCommonName` | `openvpn.commonName` |
| `openVPNUserIPAddr` | `openvpn.ip` |
| `oauth2TokenIPAddr` | `token.ip` |
| `oauth2TokenClaims` | `token.claims` |
| `username` | `user.username` |

Version 2 also exposes normalized `user.subject`, `user.email`, `user.groups`,
and `user.roles` fields. Prefer these fields when an expression should work
across generic OIDC, UserInfo, GitHub, and refresh authentication. Raw
`token.claims` can be empty when a provider supplies identity data through
another source.

Provider data and groups or roles are resolved first. The
`oauth2.openvpn-username` expression then sets the final `user.username`, and
validation and client config resolution use that final identity.

## OpenVPN username

The following options were removed or renamed:

| Version 1 option | Version 2 option |
| --- | --- |
| `oauth2.openvpn-username-claim` | `oauth2.openvpn-username` |
| `oauth2.openvpn-username-cel` | `oauth2.openvpn-username` |

`oauth2.openvpn-username` is a CEL expression and must evaluate to a string.
The default changed from the claim name `preferred_username` to
`user.username`. This uses the provider's normalized username, including
`preferred_username` for OIDC and the GitHub login for GitHub.

If you used `oauth2.openvpn-username-claim`, convert the claim name into a CEL token claim lookup:

```yaml
# Version 1
oauth2:
  openvpn-username-claim: email

# Version 2
oauth2:
  openvpn-username: user.email
```

If you used `oauth2.openvpn-username-cel`, move it to
`oauth2.openvpn-username` and translate its fields to the namespaced context:

```yaml
# Version 1
oauth2:
  openvpn-username-cel: 'oauth2TokenClaims.email.split("@")[0]'

# Version 2
oauth2:
  openvpn-username: 'user.email.split("@")[0]'
```

The environment variable for the new option is
`OPENVPN_AUTH_OAUTH2_OAUTH2_OPENVPN_USERNAME`.
Unlike version 1's provider-specific paths, the expression is applied
consistently when identity comes from an ID token, UserInfo, or the GitHub API,
and during validated refresh authentication.

## Client-specific configuration

Version 2 changes OpenVPN client-specific configuration from a single config
name lookup to an expression-based resolver.

The following options are removed:

| Version 1 option                                    | Version 2 replacement                           |
|-----------------------------------------------------|-------------------------------------------------|
| `openvpn.client-config.token-claim`                 | `openvpn.client-config.expression`              |
| `openvpn.client-config.user-selector.enabled`       | `openvpn.client-config.strategy: user-selector` |
| `openvpn.client-config.user-selector.static-values` | `openvpn.client-config.expression`              |

`openvpn.client-config.expression` is a CEL expression and must evaluate
to an ordered list of strings. It receives the full shared CEL context.
`user.username` contains the resolved OpenVPN username,
`user.groups` and `user.roles` contain normalized provider data, and
`token.claims` contains raw ID token claims.

The default strategy is now `merge`. It loads every resolved config file,
deduplicates repeated config names and identical config lines, and skips missing
config files. Keep authorization in `oauth2.validate.groups` or
`oauth2.validate.expression`; client config files only assign OpenVPN settings
such as routes.

When `openvpn.client-config.expression` returns an empty list, version 2 loads
`DEFAULT.conf`. This follows OpenVPN's `client-config-dir` default-file pattern.
When the expression returns one or more config names, missing `<name>.conf` files
are ignored by default. Set `openvpn.client-config.ignore-not-found: false` to
deny the client when a returned config file does not exist.

### Common name client config

Version 1 could use the OpenVPN common name as the implicit client config name:

```yaml
# Version 1
openvpn:
  client-config:
    enabled: true
    path: /etc/openvpn-auth-oauth2/client-config
```

In version 2, configure the resolver explicitly:

```yaml
# Version 2
openvpn:
  client-config:
    enabled: true
    path: /etc/openvpn-auth-oauth2/client-config
    expression: |
        [openvpn.commonName]
```

To use the resolved OpenVPN username instead, use `user.username`:

```yaml
openvpn:
  client-config:
    enabled: true
    path: /etc/openvpn-auth-oauth2/client-config
    expression: |
        [user.username]
```

### Token claim client config

Version 1 could read a config name from one token claim:

```yaml
# Version 1
openvpn:
  client-config:
    enabled: true
    path: /etc/openvpn-auth-oauth2/client-config
    token-claim: groups
```

In version 2, read the claim through `client-config.expression`:

```yaml
# Version 2
openvpn:
  client-config:
    enabled: true
    path: /etc/openvpn-auth-oauth2/client-config
    expression: |
        token.claims.groups
```

If the claim can contain several values, all matching config files are merged by
default.

### Profile selector

Version 1 enabled the selector with `user-selector.enabled`:

```yaml
# Version 1
openvpn:
  client-config:
    enabled: true
    path: /etc/openvpn-auth-oauth2/client-config
    token-claim: groups
    user-selector:
      enabled: true
```

In version 2, use `strategy: user-selector`:

```yaml
# Version 2
openvpn:
  client-config:
    enabled: true
    path: /etc/openvpn-auth-oauth2/client-config
    strategy: user-selector
    expression: |
        token.claims.groups
```

Static selector values also move into the expression:

```yaml
# Version 1
openvpn:
  client-config:
    enabled: true
    path: /etc/openvpn-auth-oauth2/client-config
    user-selector:
      enabled: true
      static-values:
        - corporate
        - guest
```

```yaml
# Version 2
openvpn:
  client-config:
    enabled: true
    path: /etc/openvpn-auth-oauth2/client-config
    strategy: user-selector
    expression: |
        ["corporate", "guest"]
```

### Additive group routes

To assign several config files without showing the selector, keep the default
`merge` strategy and return every allowed config name:

```yaml
oauth2:
  validate:
    groups:
      - GRP-VPN

openvpn:
  client-config:
    enabled: true
    path: /etc/openvpn-auth-oauth2/client-config
    expression: |
        user.groups.filter(g, g in [
          "GRP-VPN",
          "GRP-ADMIN",
          "GRP-NETWORK"
        ]) +
        [user.username]
```

## Token validation

Version 2 removes the following dedicated validation options:

| Version 1 option | Version 2 replacement |
| --- | --- |
| `oauth2.validate.acr` | `oauth2.validate.expression` |
| `oauth2.validate.common-name` | `oauth2.validate.expression` |
| `oauth2.validate.common-name-case-sensitive` | `oauth2.validate.expression` |
| `oauth2.validate.ipaddr` | `oauth2.validate.expression` |
| `oauth2.validate.issuer` | Removed |
| `oauth2.validate.roles` | `oauth2.validate.expression` |

`oauth2.validate.groups` stays available and does not need to be migrated.
Remove `oauth2.validate.issuer` and `CONFIG_OAUTH2_VALIDATE_ISSUER` from your
configuration. The setting did not disable issuer checks; issuer validation is
always enforced for OIDC discovery and ID token verification.

### Common name validation

Version 1 compared the OpenVPN common name with a configured ID token claim.
By default, the comparison was case-insensitive.

```yaml
# Version 1
oauth2:
  validate:
    common-name: preferred_username
```

Use a CEL expression with `lowerAscii()` for the same case-insensitive behavior:

```yaml
# Version 2
oauth2:
  validate:
    expression: |
      has(token.claims.preferred_username) &&
      openvpn.commonName.lowerAscii() == string(token.claims.preferred_username).lowerAscii()
```

If you used case-sensitive common name validation:

```yaml
# Version 1
oauth2:
  validate:
    common-name: preferred_username
    common-name-case-sensitive: true
```

Use a direct CEL comparison:

```yaml
# Version 2
oauth2:
  validate:
    expression: |
      has(token.claims.preferred_username) &&
      openvpn.commonName == string(token.claims.preferred_username)
```

### IP address validation

Version 1 compared the OpenVPN client IP address with the `ipaddr` ID token claim:

```yaml
# Version 1
oauth2:
  validate:
    ipaddr: true
```

Version 2 exposes the OpenVPN client IP as `openvpn.ip` and the token IP address claim as `token.ip`:

```yaml
# Version 2
oauth2:
  validate:
    expression: 'openvpn.ip == token.ip'
```

### Roles validation

Version 1 allowed access if at least one configured role was present in the token roles:

```yaml
# Version 1
oauth2:
  validate:
    roles:
      - admin
      - vpn-user
```

Use the normalized roles list:

```yaml
# Version 2
oauth2:
  validate:
    expression: |
      'admin' in user.roles || 'vpn-user' in user.roles
```

For GitHub provider configurations, team validation is also migrated to CEL.
The GitHub provider fetches teams from the `/user/teams` API and exposes them
through `user.roles` in the same `org:slug` format used by version 1:

```yaml
# Version 1
oauth2:
  provider: github
  validate:
    roles:
      - my-org:vpn-users
      - my-org:admins
```

```yaml
# Version 2
oauth2:
  provider: github
  validate:
    expression: |
      'my-org:vpn-users' in user.roles || 'my-org:admins' in user.roles
```

Keep organization checks with `oauth2.validate.groups`; for GitHub this still
uses the `/user/orgs` API.

### ACR validation

Version 1 used `oauth2.validate.acr` to require an Authentication Context Class Reference value:

```yaml
# Version 1
oauth2:
  validate:
    acr:
      - phr
      - phrh
```

Use CEL to check the `acr` claim:

```yaml
# Version 2
oauth2:
  validate:
    expression: |
      has(token.claims.acr) &&
      (token.claims.acr == 'phr' || token.claims.acr == 'phrh')
```

### Combining validation rules

If you used multiple removed validation options, combine them into one CEL expression:

```yaml
# Version 1
oauth2:
  validate:
    common-name: preferred_username
    ipaddr: true
    roles:
      - vpn-user
```

```yaml
# Version 2
oauth2:
  validate:
    expression: |
      has(token.claims.preferred_username) &&
      openvpn.commonName.lowerAscii() == string(token.claims.preferred_username).lowerAscii() &&
      openvpn.ip == token.ip &&
      'vpn-user' in user.roles
```

You can keep `oauth2.validate.groups` alongside CEL:

```yaml
oauth2:
  validate:
    groups:
      - vpn-users
    expression: |
      has(token.claims.acr) &&
      token.claims.acr == 'phr'
```
