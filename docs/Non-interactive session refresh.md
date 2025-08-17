# Non-interactive session refresh

By default, `openvpn-auth-oauth2` doesn't store user tokens.
This means users must log in interactively each time they authenticate, including during TLS soft-resets
(triggered by `reneg-sec`).

However, you can change this behavior by enabling the `oauth2.refresh.enabled=true` setting.
This allows `openvpn-auth-oauth2` to store either the connection ID or SessionID (`oauth2.refresh.use-session-id=true`),
accepting connections without additional login checks. SessionIDs are available in OpenVPN, if
`auth-gen-token [lifetime] external-auth` is configured on server-side.

When `oauth2.refresh.validate-user=true` is set, `openvpn-auth-oauth2`
requests a [refresh token](https://auth0.com/blog/refresh-tokens-what-are-they-and-when-to-use-them/)
during the initial connection and stores it.

The refresh tokens are stored in an in-memory key-value store and encrypted using AES.
Each token is tied to either the OpenVPN client ID or OpenVPN session ID.

If a non-interactive login attempt with the refresh token fails against the OIDC provider,
the system reverts to an interactive login process.

References:

- https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow#refresh-the-access-token
- https://curity.io/resources/learn/oauth-refresh/
- https://developer.okta.com/docs/guides/refresh-tokens/main/

# Security Considerations

If `oauth2.refresh.validate-user` is set to `false`, a refresh token is not requested and validated against the OIDC
provider.
openvpn-auth-oauth2 assumes the user is still valid and allows the user to connect without further validation.

Example: If the user opens a VPN connection and the user is deleted from the OIDC provider, the connection remains valid
until the connection lifetime is reached. Restarting the OpenVPN server will invalidate the connection unless
[non-interactive session refresh across disconnects](#non-interactive-session-refresh-across-disconnects) is configured.

# Non-interactive session refresh across disconnects

To facilitate non-interactive session refresh across disconnects,
you must enable `auth-gen-token [lifetime] external-auth` on the OpenVPN server.

- `[lifetime]` represents the duration of the token in seconds.
  Once generated, the token's lifetime cannot be extended.
  It must consider as maximum lifetime of an VPN session.
  For instance, setting the lifetime to 8 hours means
  the client will disconnect after 8 hours from the initial authentication and will need to re-authenticate.

- Setting the lifetime to 0 disables the lifetime check,
  which can be beneficial for mobile devices with unstable connections or during device sleep cycles.

If `auth-gen-token-secret [keyfile]` is configured, OpenVPN access server restarts can verify auth-tokens.
To generate a new secret, utilize `openvpn --genkey auth-token [keyfile]`.

**Note**:
Keep the keyfile secret
as anyone with access to it can generate auth tokens that the OpenVPN server will recognize as valid.
It's crucial to safeguard this file on the server.

References:

- https://openvpn.net/community-resources/reference-manual-for-openvpn-2-6/#server-options

# Troubleshooting

## OIDC Provider Issues with Refresh Tokens

Some OIDC providers may generate new refresh tokens or behave unexpectedly during non-interactive refresh requests. If you experience issues where refresh tokens are invalidated or users need to re-authenticate frequently, you can adjust the nonce behavior using the `oauth2.refresh-nonce` parameter:

- `auto` (default): Try with nonce, retry without nonce on error
- `empty`: Always use empty nonce for refresh requests
- `equal`: Use the same nonce as initial authentication

For providers like Authentik that return empty nonces on refresh (per OIDC spec), use `refresh-nonce: empty` to avoid retry logic that could invalidate refresh tokens.

## openvpn-auth-oauth2 config

<table>
<thead><tr><td>env/sysconfig configuration</td></tr></thead>
<tbody><tr><td>

```ini
CONFIG_OAUTH2_REFRESH_ENABLED=true
CONFIG_OAUTH2_REFRESH_EXPIRES=8h
CONFIG_OAUTH2_REFRESH_SECRET= # a static secret to encrypt token. Must be 16, 24 or 32
CONFIG_OAUTH2_REFRESH_USE__SESSION__ID=true
CONFIG_OPENVPN_AUTH__TOKEN__USER=true
```
</td></tr></tbody>
<thead><tr><td>yaml configuration</td></tr></thead>
<tbody><tr><td>

```yaml
oauth2:
  refresh:
    enabled: true
    expires: 8h
    secret: "..." # 16 or 24 characters
    use-session-id: true
openvpn:
  auth-token-user: true
```
</td></tr></tbody>
</table>
