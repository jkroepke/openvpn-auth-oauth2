# Upgrade V3

Version 3 includes security hardening changes that can require configuration
updates. If you do not use reverse proxy headers or the OpenVPN plugin, no action
is needed for the changes listed here.

## Reverse proxy headers

If `http.enable-proxy-headers` is enabled, `http.trusted-proxies` is now
required. openvpn-auth-oauth2 will reject the configuration if proxy headers are
enabled without at least one trusted proxy CIDR.

Use the CIDR ranges of the reverse proxies that connect directly to
openvpn-auth-oauth2:

```yaml
http:
  enable-proxy-headers: true
  trusted-proxies:
    - 127.0.0.1/32
    - 10.0.0.0/24
```

Environment variable configuration:

```ini
CONFIG_HTTP_ENABLE__PROXY__HEADERS=true
CONFIG_HTTP_TRUSTED__PROXIES=127.0.0.1/32,10.0.0.0/24
```

If openvpn-auth-oauth2 is not behind a reverse proxy, keep
`http.enable-proxy-headers` disabled.

## OpenVPN plugin

The OpenVPN plugin is no longer experimental.

The plugin management socket now requires password authentication. Existing
OpenVPN plugin configurations that pass only the listen socket must add a
password file argument, and openvpn-auth-oauth2 must use the same password for
`openvpn.password`.

Before:

```openvpn
plugin /path/to/openvpn-auth-oauth2.so "unix:///var/run/openvpn-oauth2.sock"
```

After:

```openvpn
plugin /path/to/openvpn-auth-oauth2.so "unix:///var/run/openvpn-oauth2.sock" "/etc/openvpn/oauth2-plugin-password.txt"
```

openvpn-auth-oauth2 configuration:

```yaml
openvpn:
  addr: unix:///var/run/openvpn-oauth2.sock
  password: "file:///etc/openvpn-auth-oauth2/oauth2-plugin-password.txt"
```

The two password files must contain the same password. They can be separate
files so OpenVPN and openvpn-auth-oauth2 can each read a file from the path
allowed by their service permissions.
