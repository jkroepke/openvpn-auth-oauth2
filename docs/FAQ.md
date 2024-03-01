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

When configuring `username-as-common-name` on the OpenVPN server,
it's essential to ensure that `openvpn.common-name.environment-variable-name` is also set to `username`.

This configuration is mandatory because `username-as-common-name` operates after the authentication process.
Matching the environment variable name to `username` ensures seamless functionality.
