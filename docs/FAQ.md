# FAQ

## Q: openvpn-auth-oauth2 authenticates the user on every connection

A: No, it isn’t possible to implement a Remember Me or a caching credential function directly within openvpn-auth-oauth2 or OpenVPN.
This limitation arises from the inability of openvpn-auth-oauth2 to store client cookies.
While some OIDC providers like Keycloak offer a Remember Me feature,
enabling automatic login would need implementation within the OIDC provider's settings rather than within openvpn-auth-oauth2 itself.

## Q: openvpn-auth-oauth2 re-authenticates the user on existing connections

A: Read the following documentation to understand the re-authentication behavior:

- [Non interactive session refresh](Non-interactive%20session%20refresh)

For the Google Provider,
expand the page [Providers](Providers) and look for Google consent screen always asking for permission grant.

## Q: Note Regarding Passing Usernames from OAuth2 Provider to OpenVPN

A: It's important to note that currently,
there is no mechanism to pass the username from the OAuth2 provider back to OpenVPN.
OpenVPN does not offer such an interface at present.
This limitation applies to scenarios where the IP persistence file or statistics may contain empty usernames.

For future enhancements in this area,
we encourage users to up-vote the relevant feature requests on the OpenVPN GitHub repository.
You can find and support these requests at the following link:
[Feature Request on GitHub](https://github.com/OpenVPN/openvpn/issues/299)

## Q: `mismatch: openvpn client is empty` / `username-as-common-name`

A: When setting up `username-as-common-name` on the OpenVPN server, it's crucial to also configure `openvpn.common-name.environment-variable-name` to `username`.

This configuration is indispensable because `username-as-common-name` functions post-authentication. Aligning the environment variable name with `username` guarantees smooth operation.

On authentication, it's expected that common-name is not the values of the username. That may mis-leading, because after authentication, the common name has the correct value at OpenVPN logs.

**Upstream Issue:** [OpenVPN/openvpn #498](https://github.com/OpenVPN/openvpn/issues/498#issuecomment-1939194149)

## Q: Options error: No client-side authentication method is specified.

A: Although openvpn-auth-oauth2 theoretically doesn't require client-side authentication, the OpenVPN client expects it.

**Upstream Issue:** [OpenVPN/openvpn #501](https://github.com/OpenVPN/openvpn/issues/501) (Please react with :+1: if you're affected.)

**Potential Workarounds:**

1. **Configure Client Certificates**
    Implement client certificates to enable client-side authentication.

2. **Use Inline auth-user-pass**
    OpenVPN accepts `auth-user-pass` for client-side authentication. You can define the username and password inline to prevent the OpenVPN GUI from requesting a password.

    ```
    <auth-user-pass>
    username
    password
    </auth-user-pass>
    ```

    Note: The username/password can be any dummy value as they won't be validated by openvpn-auth-oauth2 or OpenVPN itself.

## Q: `Provider did not return a id_token. Validation of user data is not possible.` is logged, but my provider is returning an id_token.

A: This could happen, if `oauth2.endpoint.auth` and `oauth2.endpoint.token` are defined. In this case,
the underlying works in OAUTH2 mode, and the id_token is not recognized.
If user validation is needed, remove `oauth2.endpoint.auth` and `oauth2.endpoint.token` from the configuration.

## Q: Why openvpn-auth-oauth2 logout the user from OIDC server after the VPN session was terminated?

A: The openvpn-auth-oauth2 plugin doesn’t log out the user from the OIDC server
after the VPN session ends because the OpenID Connect (OIDC) protocol’s end session endpoint,
while available, isn’t suitable in this context.
The end session endpoint generates a URL
intended for the end user to manually initiate the logout process via their browser.
Since OpenVPN operates without direct interaction with the user's browser upon logout,
there's no mechanism to automatically open the URL for the user.

Instead of attempting a user logout, the recommended approach to configure short session lifetimes.
This ensures that OIDC sessions aren’t reused after a VPN session terminates, minimizing the risk of session misuse.

It's also worth noting that for an attacker to reuse a session with openvpn-auth-oauth2,
they’d need a valid OpenVPN session cookie from an active and authenticated connection.
This requirement provides an additional layer of security,
as getting a cookie is highly unlikely without a prior compromise.

## Q: If the refresh token expires, OpenVPN keeps opening browser sessions endlessly. How can I prevent that?

A: This behavior can occur if the OpenVPN client is configured to retry authentication using the auth-retry option.
By default, OpenVPN does not retry after an AUTH_FAILURE, but if auth-retry is set (e.g., to interact or nointeract), it may trigger repeated browser sessions.

In addition, some server-side settings can cause re-authentication loops.

A common issue is the inactive directive on the OpenVPN server.
If it’s set lower than the authentication timeout, OpenVPN may interrupt the session too early, restarting the auth process.

To avoid this, ensure the inactive timeout is higher than the auth timeout.
You can find the auth timeout value in the OpenVPN server logs by searching for:

```
AUTH_PENDING,timeout
```

If the log shows timeout=60, then set inactive to at least 65 — always add 5 seconds to the timeout value as a safety margin.
