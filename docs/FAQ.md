# FAQ

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

2. **Utilize Inline auth-user-pass**
   OpenVPN accepts `auth-user-pass` for client-side authentication. You can define the username and password inline to prevent the OpenVPN GUI from requesting a password.

   ```
   <auth-user-pass>
   username
   password
   </auth-user-pass>
   ```

   Note: The username/password can be any dummy value as they won't be validated by openvpn-auth-oauth2 or OpenVPN itself.

## Q: Can a Remember Me function be implemented in openvpn-auth-oauth2?

A: No, it is not feasible to implement a Remember Me function directly within openvpn-auth-oauth2 or OpenVPN. This limitation arises from the inability of openvpn-auth-oauth2 to store client cookies. While some OIDC providers like Keycloak offer a Remember Me feature, enabling automatic login would require implementation within the OIDC provider's settings rather than within openvpn-auth-oauth2 itself.

## Q: In logs, I see `Provider did not return a id_token. Validation of user data is not possible.`, but my provider is returning an id_token.

A: This could happen, if `oauth2.endpoint.auth` and `oauth2.endpoint.token` are defined. In this case, the underlying works in OAUTH2 mode, and the id_token is not recognized. If you want to use the user validation, you should remove `oauth2.endpoint.auth` and `oauth2.endpoint.token` from your configuration.
