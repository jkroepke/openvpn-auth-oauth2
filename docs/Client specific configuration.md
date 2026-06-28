# Client specific configuration

openvpn-auth-oauth2 can load OpenVPN client configuration snippets from a
configured directory and send the merged result through the OpenVPN management
interface.

Enable the feature with `--openvpn.client-config.enabled` and set
`--openvpn.client-config.path` to the directory that contains the configuration
files.

When `openvpn.client-config.enabled` is false, no client configuration file is
loaded, including `DEFAULT.conf`.

Each resolved config name loads `<name>.conf` from that directory. Filenames
must satisfy Go's `fs.ValidPath`; absolute paths and `.` or `..` path elements
are rejected. Symbolic links are followed only when their targets remain inside
the configured client config directory.

If the expression returns an empty list, openvpn-auth-oauth2 loads
`DEFAULT.conf`, matching OpenVPN's `client-config-dir` default-file pattern. If
a returned `<name>.conf` file is not found, the default behavior is to ignore the
missing file and continue. Set `openvpn.client-config.ignore-not-found: false`
to deny the client instead.

## Resolver

Client config names are resolved with
`openvpn.client-config.expression`. The expression is [CEL](CEL%20Language%20Features.md) and must return
an ordered string list.

The expression receives:

- `oauth2TokenClaims`: the OAuth2 ID token claims.
- `openVPNUserCommonName`: the OpenVPN user common name.
- `username`: the resolved OpenVPN username.

Example:

```yaml
oauth2:
  openvpn-username: oauth2TokenClaims.preferred_username
  validate:
    groups:
      - GRP-VPN

openvpn:
  override-username: true
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

For `alice@example.edu` with `GRP-VPN` and `GRP-ADMIN`, this loads:

1. `GRP-VPN.conf`
2. `GRP-ADMIN.conf`
3. `alice@example.edu.conf`

## Strategy

`openvpn.client-config.strategy` controls how resolved config names are applied.

The default is `merge`.

### merge

`merge` loads all resolved config files in resolver order.

Duplicate config names are loaded once. Duplicate config lines are sent once,
preserving the first occurrence. Missing config files are skipped when
`openvpn.client-config.ignore-not-found` is true, so authorization must still be
enforced with `oauth2.validate.groups` or `oauth2.validate.expression`.
This lets the expression return every valid role or group name and leave
unconfigured names without a matching `.conf` file.

```yaml
openvpn:
  client-config:
    enabled: true
    path: /etc/openvpn-auth-oauth2/client-config
    strategy: merge
    expression: |
        (["base-vpn"] + oauth2TokenClaims.roles).distinct()
```

With this configuration, a role named `admin-routes` loads
`admin-routes.conf`. A role without a matching file is ignored while
`openvpn.client-config.ignore-not-found` is true.

Groups can also map to several shared config files. This is useful when
different groups should receive overlapping route sets:

```yaml
openvpn:
  client-config:
    enabled: true
    path: /etc/openvpn-auth-oauth2/client-config
    strategy: merge
    expression: |
        oauth2TokenClaims.groups
          .map(g, {
            "GRP-VPN": ["base-vpn"],
            "GRP-ADMIN": ["base-vpn", "admin-routes"],
            "GRP-NETWORK": ["base-vpn", "network-routes"]
          }[g])
          .flatten()
          .distinct()
```

The map returns a list of config names for each group. `flatten()` converts the
list of lists into one ordered list, and `distinct()` removes repeated entries
such as `base-vpn`.

Use this pattern when every input group is expected to exist in the map. If the
token can contain unrelated groups, prefer returning the group names directly and
let `openvpn.client-config.ignore-not-found` skip missing files.

### user-selector

`user-selector` shows the profile selector when the resolver returns more than
one config name. If the resolver returns one config name, that config is used
directly. If the resolver returns an empty list, `DEFAULT.conf` is used.

```yaml
openvpn:
  client-config:
    enabled: true
    path: /etc/openvpn-auth-oauth2/client-config
    strategy: user-selector
    expression: |
        ["corporate", "guest"] +
        oauth2TokenClaims.groups.filter(g, g.startsWith("vpn-profile-"))
```
