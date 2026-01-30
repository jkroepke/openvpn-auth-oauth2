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

# Relationship between reneg-sec and auth-gen-token

Understanding the interaction between `reneg-sec` and `auth-gen-token` is crucial for optimal session management.

## How They Work Together

- **`reneg-sec`**: Controls the TLS renegotiation (soft reset) interval. Can be set on both client and server; the lower value determines when renegotiation occurs. Default is 3600 seconds (1 hour).
- **`auth-gen-token [lifetime] [renewal-time] external-auth`**: Generates authentication tokens that can be renewed during TLS renegotiations.
  - `lifetime`: Maximum duration the token remains valid (in seconds). Once expired, the user must re-authenticate.
  - `renewal-time`: (Optional) The token expires if it remains idle (not renewed) for more than `2 * renewal-time` seconds. Defaults to the value of `reneg-sec` if not specified.

## Token Expiration Rules

An auth token expires under either condition:
1. The `lifetime` has been reached (absolute expiration)
2. The token has not been renewed for more than `2 * renewal-time` seconds (idle timeout)

## Best Practices

For optimal configuration:

1. **Set `reneg-sec` to a reasonably low value** (e.g., 3600 seconds = 1 hour)
   - This ensures regular token renewal attempts
   - Prevents tokens from becoming idle for too long
   
2. **Set `lifetime` to a reasonably high value** (e.g., 86400 seconds = 24 hours)
   - Allows long-lived sessions without re-authentication
   - Users only need to log in once per day (or per lifetime period)

3. **Optional: Explicitly set `renewal-time`** if you need different renewal behavior
   - If not specified, it defaults to `reneg-sec`.
   - Setting it to a higher value than `reneg-sec` can extend the idle timeout.

## Example Configuration

```
# OpenVPN server configuration
reneg-sec 3600                                    # Renegotiate every hour
auth-gen-token 86400 external-auth                # 24-hour lifetime (renewal-time omitted, defaults to reneg-sec)
auth-gen-token-secret /path/to/token.key          # Persist tokens across server restarts
```

Alternatively, explicitly specify renewal-time:
```
# OpenVPN server configuration
reneg-sec 3600                                    # Renegotiate every hour
auth-gen-token 86400 3600 external-auth           # 24-hour lifetime, 1-hour renewal-time
auth-gen-token-secret /path/to/token.key          # Persist tokens across server restarts
```

With this configuration:
- TLS renegotiation occurs every hour (server's `reneg-sec 3600` setting)
- The auth token is renewed during each renegotiation (non-interactive if refresh is enabled)
- The token remains valid for up to 24 hours from initial authentication (`lifetime 86400`)
- The token expires if not renewed for more than 2 hours (`2 * renewal-time` = `2 * 3600` = 7200 seconds)
  - This provides a grace period allowing one missed renegotiation attempt before token expiration
  - In practice: if the client is disconnected/unreachable for more than 2 hours, the token expires

## Important Notes

- If `oauth2.refresh.enabled=true` is configured in `openvpn-auth-oauth2`, token renewals during `reneg-sec` renegotiations will be non-interactive (no browser popup).
- Without refresh enabled, users must log in interactively at each `reneg-sec` interval.
- Setting `reneg-sec 0` on the client-side disables TLS renegotiation, which may be useful for mobile devices but requires careful consideration of security implications.

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
