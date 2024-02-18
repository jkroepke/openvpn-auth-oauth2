# openvpn-auth-oauth2 OpenVPN auth plugin

Status: Experimental (and will likely remain so)

This is a native OpenVPN plugin (`openvpn-auth-oauth2.so`) that authenticates users against an OAuth2 provider.

The plugin has some security issues and is not recommended for production use:

- The plugin exposes an HTTP server that listens on all interfaces. This is a security risk, because it exposes the
  OpenVPN server to the public. If there is an security breach in the plugin, an attacker could gain access to the
  all sensitive data where the OpenVPN server has access to.
