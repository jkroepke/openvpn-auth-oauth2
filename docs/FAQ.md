# FAQ

## Note Regarding Passing Usernames from OAuth2 Provider to OpenVPN

It's important to note that currently,
there is no mechanism to pass the username from the OAuth2 provider back to OpenVPN.
OpenVPN does not offer such an interface at present.
This limitation applies to scenarios where the IP persistence file or statistics may contain empty usernames.

For future enhancements in this area,
we encourage users to up-vote the relevant feature requests on the OpenVPN GitHub repository.
You can find and support these requests at the following link:
[Feature Request on GitHub](https://github.com/OpenVPN/openvpn/issues/299)

## username-as-common-name

When setting up `username-as-common-name` on the OpenVPN server, it's crucial to also configure `openvpn.common-name.environment-variable-name` to `username`.

This configuration is indispensable because `username-as-common-name` functions post-authentication. Aligning the environment variable name with `username` guarantees smooth operation.

## Options error: No client-side authentication method is specified.

Although openvpn-auth-oauth2 theoretically doesn't require client-side authentication, the OpenVPN client expects it.

**Upstream Issue:** [GitHub Issue #501](https://github.com/OpenVPN/openvpn/issues/501) (Please react with :+1: if you're affected.)

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
