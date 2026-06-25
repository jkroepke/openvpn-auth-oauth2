# Upgrade V2

Version 2 removes the separate OpenVPN username claim option and keeps a single CEL-based username option.

## OpenVPN username

The following options were removed or renamed:

| Version 1 option | Version 2 option |
| --- | --- |
| `oauth2.openvpn-username-claim` | `oauth2.openvpn-username` |
| `oauth2.openvpn-username-cel` | `oauth2.openvpn-username` |

`oauth2.openvpn-username` is a CEL expression and must evaluate to a string.
The default changed from the claim name `preferred_username` to the equivalent CEL expression `oauth2TokenClaims.preferred_username`.

If you used `oauth2.openvpn-username-claim`, convert the claim name into a CEL token claim lookup:

```yaml
# Version 1
oauth2:
  openvpn-username-claim: email

# Version 2
oauth2:
  openvpn-username: oauth2TokenClaims.email
```

If you used `oauth2.openvpn-username-cel`, keep the same expression and move it to `oauth2.openvpn-username`:

```yaml
# Version 1
oauth2:
  openvpn-username-cel: 'oauth2TokenClaims.email.split("@")[0]'

# Version 2
oauth2:
  openvpn-username: 'oauth2TokenClaims.email.split("@")[0]'
```

The environment variable for the new option is `CONFIG_OAUTH2_OPENVPN__USERNAME`.

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
to an ordered list of strings. It receives `oauth2TokenClaims`, which contains
the OAuth2 ID token claims, and `openVPNUserCommonName`, which contains the
OpenVPN common name. It also receives `username`, which contains the resolved
OpenVPN username after `oauth2.openvpn-username` has been evaluated.

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
        [openVPNUserCommonName]
```

To use the resolved OpenVPN username instead, use `username`:

```yaml
openvpn:
  client-config:
    enabled: true
    path: /etc/openvpn-auth-oauth2/client-config
    expression: |
        [username]
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
        oauth2TokenClaims.groups
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
        oauth2TokenClaims.groups
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
        oauth2TokenClaims.groups.filter(g, g in [
          "GRP-VPN",
          "GRP-ADMIN",
          "GRP-NETWORK"
        ]) +
        [username]
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
      has(oauth2TokenClaims.preferred_username) &&
      openVPNUserCommonName.lowerAscii() == string(oauth2TokenClaims.preferred_username).lowerAscii()
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
      has(oauth2TokenClaims.preferred_username) &&
      openVPNUserCommonName == string(oauth2TokenClaims.preferred_username)
```

### IP address validation

Version 1 compared the OpenVPN client IP address with the `ipaddr` ID token claim:

```yaml
# Version 1
oauth2:
  validate:
    ipaddr: true
```

Version 2 exposes the OpenVPN client IP as `openVPNUserIPAddr` and the token IP address claim as `oauth2TokenIPAddr`:

```yaml
# Version 2
oauth2:
  validate:
    expression: 'openVPNUserIPAddr == oauth2TokenIPAddr'
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

Use CEL to check the `roles` claim directly:

```yaml
# Version 2
oauth2:
  validate:
    expression: |
      has(oauth2TokenClaims.roles) &&
      ('admin' in oauth2TokenClaims.roles || 'vpn-user' in oauth2TokenClaims.roles)
```

For GitHub provider configurations, team validation is also migrated to CEL.
The GitHub provider still fetches teams from the `/user/teams` API and exposes
them through `oauth2TokenClaims.roles` in the same `org:slug` format used by
version 1:

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
      has(oauth2TokenClaims.roles) &&
      ('my-org:vpn-users' in oauth2TokenClaims.roles || 'my-org:admins' in oauth2TokenClaims.roles)
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
      has(oauth2TokenClaims.acr) &&
      (oauth2TokenClaims.acr == 'phr' || oauth2TokenClaims.acr == 'phrh')
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
      has(oauth2TokenClaims.preferred_username) &&
      openVPNUserCommonName.lowerAscii() == string(oauth2TokenClaims.preferred_username).lowerAscii() &&
      openVPNUserIPAddr == oauth2TokenIPAddr &&
      has(oauth2TokenClaims.roles) &&
      'vpn-user' in oauth2TokenClaims.roles
```

You can keep `oauth2.validate.groups` alongside CEL:

```yaml
oauth2:
  validate:
    groups:
      - vpn-users
    expression: |
      has(oauth2TokenClaims.acr) &&
      oauth2TokenClaims.acr == 'phr'
```
