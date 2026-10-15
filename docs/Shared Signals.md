# Shared Signals (session revocation)

An established VPN connection normally keeps running until OpenVPN asks for
reauthentication, for example at the next `reneg-sec` renegotiation. If the
identity provider ends a user's session in the meantime, the VPN connection
stays up.

With `ssf.enabled`, `openvpn-auth-oauth2` acts as a receiver of the
[OpenID Shared Signals Framework (SSF)](https://openid.net/specs/openid-sharedsignals-framework-1_0.html).
It polls the identity provider for
[CAEP `session-revoked`](https://openid.net/specs/openid-caep-1_0.html#name-session-revoked)
events and terminates the matching OpenVPN sessions within one poll interval.

> [!IMPORTANT]
> SSF requires the [direct management interface](Configuration#direct-management-interface).
> The [OpenVPN plugin](OpenVPN%20Plugin) can't terminate clients, so
> `openvpn-auth-oauth2` refuses to start with `ssf.enabled` in plugin mode.

## How it works

1. At startup, `openvpn-auth-oauth2` reads the transmitter configuration
   metadata from the well-known path `/.well-known/ssf-configuration` of the
   issuer (see [Other providers](#other-providers)), fetches the
   transmitter's signing keys from its `jwks_uri`, and reads the stream
   configuration from its `configuration_endpoint`. The stream must already
   exist; `openvpn-auth-oauth2` doesn't create one.
2. It polls the stream's `endpoint_url` with
   [RFC 8936 poll delivery](https://www.rfc-editor.org/rfc/rfc8936).
3. Each Security Event Token (SET) is verified: signature, `typ`, `iss`,
   `aud`, `iat`, and `jti`. A token that fails verification is reported back to
   the transmitter as an error. Other event types, and subjects that can't be
   matched, are acknowledged and ignored.
4. The subject of a `session-revoked` event is matched against the OIDC
   identity every client logged in with. For every match,
   `openvpn-auth-oauth2` deletes the stored refresh token of the client and,
   if the client is connected, sends `client-kill <cid> HALT` to OpenVPN.
5. The event is acknowledged only after the revocation succeeded. If it failed,
   the transmitter delivers the event again with a later poll.

Discovery errors stop the startup, so a misconfigured transmitter is noticed
immediately. Errors while polling are logged and retried with an increasing
delay of up to 5 minutes.

### Which sessions are revoked

| Event subject                                           | Revoked OpenVPN sessions                                          |
|---------------------------------------------------------|-------------------------------------------------------------------|
| `complex` subject with a `session` member               | Sessions whose ID token had the same `sid` (and user, if present). |
| `iss_sub` subject, or `complex` with only a `user` member | All sessions of the user, if `ssf.user-level-revocation` is true.  |
| `email` subject                                         | All sessions with that email address, if `ssf.subject.allow-email` and `ssf.user-level-revocation` are true. |

Most transmitters send `iss_sub` subjects, so keep `ssf.user-level-revocation`
enabled. The issuer and subject of the event must equal the `iss` and `sub`
claims of the ID token the client logged in with.

Clients that connected without OIDC authentication, for example through
`openvpn.bypass.common-names`, aren't tracked and never revoked.

The identities are kept in memory. A configuration reload with `SIGUSR1` keeps
them, but after a restart of `openvpn-auth-oauth2`, clients that are still
connected can only be revoked once they authenticate again, for example at the
next `reneg-sec` renegotiation.

### Reconnecting after a revocation

`HALT` tells the client not to reconnect. A client that reconnects anyway
lands in the interactive browser login, because its refresh token is gone. The
identity provider has revoked the session itself, so the user must log in
again there.

If OpenVPN runs with `auth-gen-token`, use the `external-auth` flag:

```
auth-gen-token 28800 external-auth
```

Without `external-auth`, OpenVPN accepts a reconnecting client with a valid
auth token on its own and never asks `openvpn-auth-oauth2`, so a revoked client
could reconnect until its auth token expires. See
[Non-interactive session refresh](Non-interactive%20session%20refresh#non-interactive-session-refresh-across-disconnects).

## Configuration

```yaml
oauth2:
  issuer: "https://keycloak.example.com/realms/example"
  client:
    id: "openvpn-auth-oauth2"
    secret: "file:///etc/openvpn-auth-oauth2/client-secret"
ssf:
  enabled: true
  # issuer: ""  # defaults to oauth2.issuer
  poll:
    # token: ""  # defaults to a client credentials access token of oauth2.client
    scopes: ["ssf.read"]
    interval: 30s
    max-events: 100
  max-age: 1h
  user-level-revocation: true
  subject:
    allow-email: false
```

| Setting                       | Default          | Description                                                                                                                                  |
|-------------------------------|------------------|----------------------------------------------------------------------------------------------------------------------------------------------|
| `ssf.enabled`                 | `false`          | Receive SSF events and terminate revoked sessions.                                                                                           |
| `ssf.issuer`                  | `oauth2.issuer`  | Issuer of the SSF transmitter. Must use `https://`. It must equal the `issuer` in the transmitter metadata and the `iss` of every event.      |
| `ssf.poll.token`              |                  | Static bearer token for the transmitter. If empty, `openvpn-auth-oauth2` requests and renews an access token with the client credentials grant of `oauth2.client`. Supports `file://`. |
| `ssf.poll.scopes`             | `ssf.read`       | Scopes of the client credentials access token. Ignored if `ssf.poll.token` is set.                                                          |
| `ssf.poll.interval`           | `30s`            | Wait time between polls that return no events. Also the first retry delay after an error.                                                    |
| `ssf.poll.max-events`         | `100`            | Maximum number of events per poll.                                                                                                           |
| `ssf.max-age`                 | `1h`             | Events issued longer ago are rejected. Also the replay protection window.                                                                    |
| `ssf.user-level-revocation`   | `true`           | Revoke all sessions of a user for events without a session identifier.                                                                     |
| `ssf.subject.allow-email`     | `false`          | Accept events whose subject is an email address. Email addresses can be reassigned; prefer `iss_sub`.                                         |

The poll endpoint, the audience, and the signing keys aren't configurable; they
come from the transmitter metadata and the stream configuration. All of them
must use `https://`.

The client credentials grant authenticates like the login does: with
`oauth2.client.secret`, or with a `private_key_jwt` assertion if
`oauth2.client.private-key` is set. The OAuth2 client therefore needs the
client credentials grant (a service account) enabled at the provider.

## Trust model

- Events are accepted only from the configured issuer and only if they're
  signed with an asymmetric key from the transmitter's `jwks_uri`. Keys are
  fetched again when an unknown key ID appears.
- Events must be addressed to the audience of the stream.
- Every event ID (`jti`) is processed only once within `ssf.max-age`. The
  replay protection is held in memory and starts empty after a restart.
- `openvpn-auth-oauth2` only ends sessions; an SSF event can never start or
  extend one.

## Provider setup

| Provider                                                                                                | `session-revoked` | Poll delivery | Notes                                                                                     |
|---------------------------------------------------------------------------------------------------------|-------------------|---------------|-------------------------------------------------------------------------------------------|
| [Keycloak](https://www.keycloak.org/securing-apps/ssf-support)                                          | Yes               | Yes           | Experimental feature, enable with `--features=ssf`. Polls always return immediately.      |
| [Okta](https://help.okta.com/oie/en-us/Content/Topics/Apps/configure-shared-signal-transmitter.htm)     | Yes               | Not verified  | Requires the `ssf.read` and `ssf.manage` scopes on the receiver app.                      |
| Google Workspace, Microsoft Entra ID                                                                    | No                |               | Neither offers a `session-revoked` transmitter for third-party receivers.                 |

### Keycloak

Keycloak's SSF support is experimental and not recommended for production yet.

1. Start Keycloak with `--features=ssf`.
2. In **Realm settings** → **SSF**, enable the transmitter. The realm issuer
   `https://<host>/realms/<realm>` is then also the SSF issuer, so
   `ssf.issuer` can stay empty.
3. Open the OIDC client used by `openvpn-auth-oauth2`. Enable
   **Client authentication** and **Service accounts roles**, then switch on
   **SSF enabled**.
4. In the **SSF** → **Receiver** tab, allow **Poll delivery**, select the
   `session-revoked` event under **Supported events**, and keep the
   **User subject format** `iss_sub`.
5. In the **SSF** → **Stream** tab, create a stream with the delivery method
   **Poll**.
6. Configure `openvpn-auth-oauth2`:

   ```yaml
   ssf:
     enabled: true
   ```

   The default scope `ssf.read` is sufficient to read the stream and poll it.

Keycloak allows one stream per receiver client. Keycloak's documentation
doesn't list which actions emit `session-revoked`; check the behavior of your
Keycloak version, for example by ending a user session in the admin console
and watching the `openvpn-auth-oauth2` log.

### Other providers

Any transmitter that implements SSF 1.0 with stream configuration and poll
delivery works. The transmitter must:

- publish its metadata with the well-known path inserted between host and
  path of the issuer, as SSF 1.0 requires
  (`https://example.com/.well-known/ssf-configuration/tenant` for the issuer
  `https://example.com/tenant`), or appended to the issuer
  (`https://example.com/tenant/.well-known/ssf-configuration`),
- return exactly one stream for the receiver from its `configuration_endpoint`,
  with the delivery method `urn:ietf:rfc:8936`, and
- sign events with an asymmetric algorithm (RSA, RSA-PSS, ECDSA, or EdDSA).

## Monitoring

The following metrics are available on the [metrics endpoint](Metrics):

- `openvpn_auth_oauth2_ssf_events_total{outcome}`
- `openvpn_auth_oauth2_ssf_sessions_revoked_total{scope}`
- `openvpn_auth_oauth2_ssf_poll_errors_total`
- `openvpn_auth_oauth2_ssf_last_successful_poll_timestamp_seconds`

Alert if the last successful poll is older than a few poll intervals:

```promql
time() - openvpn_auth_oauth2_ssf_last_successful_poll_timestamp_seconds > 300
```
