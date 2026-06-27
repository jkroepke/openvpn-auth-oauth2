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
