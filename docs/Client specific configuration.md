# Client specific configuration

## Introduction

This document describes the client-specific configuration options of openvpn-auth-oauth2.
It mimics the client-config-dir capability of OpenVPN.
But instead the client username, a token claim is used as config identifier.

## Configuration

The feature must be enabled with `--openvpn.client-config.enabled`.
`--openvpn.client-config.path` points to a directory where the client-specific configuration files are stored.

openvpn-auth-oauth2 looks for a file
named after the token claim or common name with `.conf` suffix in the client config directory.

## User Profile Selector

The user profile selector feature allows users to choose their client configuration profile through a web UI after OAuth2 authentication. This is useful when:
- Users need access to different VPN configurations (e.g., different network segments, access levels)
- Profile assignments are determined by OAuth2 token claims (e.g., roles, groups, departments)
- You want to provide a self-service experience for profile selection

### Configuration Options

#### Enable Profile Selector

```bash
--openvpn.client-config.user-selector.enabled
```

**Environment Variable:** `CONFIG_OPENVPN_CLIENT__CONFIG_USER__SELECTOR_ENABLED`

**Default:** `false`

When enabled, openvpn-auth-oauth2 will display a profile selection UI after successful OAuth2 authentication. Users can choose from available profiles before connecting to the VPN.

Profile options are populated from:
- Static values configured via `--openvpn.client-config.user-selector.static-values`
- Token claim values from `--openvpn.client-config.token-claim` (if configured)

**Note:** The profile selector only appears when there are 2 or more profiles available. If only one profile is available, it will be automatically selected without showing the UI.

#### Static Profile Values

```bash
--openvpn.client-config.user-selector.static-values value1,value2,value3
```

**Environment Variable:** `CONFIG_OPENVPN_CLIENT__CONFIG_USER__SELECTOR_STATIC__VALUES`

**Default:** (empty)

A comma-separated list of static profile names that are always available in the profile selector UI. These profiles will be displayed as selectable options for all authenticated users, regardless of their token claims.

**Example:**
```bash
--openvpn.client-config.user-selector.static-values corporate,guest,remote
```

This would show three profiles (corporate, guest, remote) to every user.


### How It Works

1. User completes OAuth2 authentication
2. openvpn-auth-oauth2 extracts available profiles from:
   - Static values (from `--openvpn.client-config.user-selector.static-values`)
   - Token claim values (from `--openvpn.client-config.token-claim`, if configured
   - supports both string and array values)
3. Based on the number of profiles:
   - **0 profiles:** Falls back to default behavior (uses username or token claim from `--openvpn.client-config.token-claim`)
   - **1 profile:** Automatically selects that profile without showing UI
   - **2+ profiles:** Displays profile selector UI to the user
4. User selects a profile
5. OpenVPN client configuration is applied based on the selected profile name

### Profile Configuration Files

After a profile is selected, openvpn-auth-oauth2 looks for a configuration file in the client config directory:

```
<client-config-path>/<selected-profile>.conf
```

For example, if a user selects the "corporate" profile, the file would be:
```
/path/to/client-config/corporate.conf
```

### Example Configurations

#### Example 1: Static Profiles Only

Allow all users to choose from three predefined profiles:

```yaml
openvpn:
  client-config:
    enabled: true
    path: /etc/openvpn/client-config
    user-selector:
      enabled: true
      static-values:
        - full-access
        - limited-access
        - guest-access
```

Or via command line:
```bash
--openvpn.client-config.enabled \
--openvpn.client-config.path=/etc/openvpn/client-config \
--openvpn.client-config.user-selector.enabled \
--openvpn.client-config.user-selector.static-values=full-access,limited-access,guest-access
```

#### Example 2: Dynamic Profiles from Token Claims

Profiles are determined by the user's "groups" claim:

```yaml
openvpn:
  client-config:
    enabled: true
    path: /etc/openvpn/client-config
    token-claim: groups
    user-selector:
      enabled: true
```

If a user's ID token contains:
```json
{
  "groups": ["engineering", "vpn-users"]
}
```

They will see profiles "engineering" and "vpn-users" in the selector.

#### Example 3: Combined Static and Dynamic Profiles

Provide a "guest" profile to everyone, plus role-based profiles:

```yaml
openvpn:
  client-config:
    enabled: true
    path: /etc/openvpn/client-config
    token-claim: roles
    user-selector:
      enabled: true
      static-values:
        - guest
```

If a user has `"roles": ["admin", "developer"]` in their token, they will see three profiles:
- guest (static)
- admin (from token)
- developer (from token)

### Security Considerations

- The profile selector validates that the selected profile is in the list of allowed profiles (from static values and/or token claims)
- Invalid profile selections are rejected
- All profile data is encrypted during transmission between the browser and server
- Profile selection requires a valid OAuth2 authentication session

### Interaction with Other Settings

The user profile selector takes precedence over the `--openvpn.client-config.token-claim` setting when enabled. The flow is:

1. If `user-selector.enabled` is true and multiple profiles are available → Show profile selector
2. If `user-selector.enabled` is true and one profile is available → Use that profile automatically
3. Otherwise → Fall back to standard behavior using `--openvpn.client-config.token-claim` if configured
