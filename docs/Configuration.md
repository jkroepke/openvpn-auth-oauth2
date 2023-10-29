# Configuration

The preferred way to configure openvpn-auth-oauth2 is via environment variables. If you install the openvpn-auth-auth2 via
Linux package, use the file `/etc/sysconfig/openvpn-auth-oauth2` to configure openvpn-auth-oauth2.

## Supported configuration properties

```
Usage of openvpn-auth-oauth2:
      --config string                        path to one .yaml config files. (env: CONFIG_CONFIG)
      --http.baseurl string                  listen addr for client listener. (env: CONFIG_HTTP_BASEURL) (default "http://localhost:9000")
      --http.template string   Path to a HTML file which is displayed at the end of the screen. (env: CONFIG_HTTP_TEMPLATE)
      --http.cert string                     Path to tls server certificate. (env: CONFIG_HTTP_CERT)
      --http.check.ipaddr                    Check if client IP in http and VPN is equal. (env: CONFIG_HTTP_CHECK_IPADDR)
      --http.enable-proxy-headers            Use X-Forward-For http header for client ips. (env: CONFIG_HTTP_ENABLE_PROXY_HEADERS)
      --http.key string                      Path to tls server key. (env: CONFIG_HTTP_KEY)
      --http.listen string                   listen addr for client listener. (env: CONFIG_HTTP_LISTEN) (default ":9000")
      --http.secret string                   Cookie secret. (16 or 24 symbols) (env: CONFIG_HTTP_SECRET)
      --http.tls                             enable TLS listener. (env: CONFIG_HTTP_TLS)
      --log.format string                    log format. json or console (env: CONFIG_LOG_FORMAT) (default "json")
      --log.level string                     log level. (env: CONFIG_LOG_LEVEL) (default "info")
      --oauth2.authorize-params string       additional url query parameter to authorize endpoint. (env: CONFIG_OAUTH2_AUTHORIZE_ENDPOINT)
      --oauth2.client.id string              oauth2 client id. (env: CONFIG_OAUTH2_CLIENT_ID)
      --oauth2.client.secret string          oauth2 client secret. (env: CONFIG_OAUTH2_CLIENT_SECRET)
      --oauth2.endpoint.auth string          custom oauth2 auth endpoint. (env: CONFIG_OAUTH2_ENDPOINT_AUTH)
      --oauth2.endpoint.discovery string     custom oauth2 discovery url. (env: CONFIG_OAUTH2_ENDPOINT_DISCOVERY)
      --oauth2.endpoint.token string         custom oauth2 token endpoint. (env: CONFIG_OAUTH2_ENDPOINT_TOKEN)
      --oauth2.issuer string                 oauth2 issuer. (env: CONFIG_OAUTH2_ISSUER)
      --oauth2.provider string               oauth2 provider. (env: CONFIG_OAUTH2_PROVIDER) (default "generic")
      --oauth2.scopes strings                oauth2 token scopes. (env: CONFIG_OAUTH2_SCOPES) (default [openid,profile])
      --oauth2.validate.common_name string   validate common_name from OpenVPN with IDToken claim. (env: CONFIG_OAUTH2_VALIDATE_COMMON_NAME)
      --oauth2.validate.groups strings       oauth2 required user groups. (env: CONFIG_OAUTH2_VALIDATE_GROUPS)
      --oauth2.validate.ipaddr               validate client ipaddr between VPN and OIDC token. (env: CONFIG_OAUTH2_VALIDATE_IPADDR)
      --oauth2.validate.issuer               validate issuer from oidc discovery. (env: CONFIG_OAUTH2_VALIDATE_ISSUER) (default true)
      --oauth2.validate.roles strings        oauth2 required user roles. (env: CONFIG_OAUTH2_VALIDATE_ROLES)
      --openvpn.addr string                  openvpn management interface addr. Must start with unix:// or tcp:// (env: CONFIG_OPENVPN_ADDR) (default "unix:///run/openvpn/server.sock")
      --openvpn.auth-token-user              Define auth-token-user for all sessions. (env: CONFIG_OPENVPN_AUTH_TOKEN_USER) (default true)
      --openvpn.bypass.cn strings            bypass oauth authentication for CNs. (env: CONFIG_OAUTH2_BYPASS_CN)
      --openvpn.password string              openvpn management interface password. (env: CONFIG_OPENVPN_PASSWORD)
      --version                              shows versions
```

## Configuration openvpn-auth-oauth2
openvpn-auth-oauth2 starts a http listener which needs to be accessible from OpenVPN client before the VPN connection is established.
By default, the http listener runs on :9000.

It's highly recommend to put openvpn-auth-oauth2 behind a reverse proxy which terminates the TLS connections. It's important to configure
`CONFIG_HTTP_BASE_URL` because openvpn-auth-oauth2 need to know the redirect url.

Example:
```conf
# openvpn-auth-oauth2 config file
CONFIG_HTTP_LISTEN=:9000
CONFIG_HTTP_BASE_URL=https://login.example.com
```

## Setup OpenVPN server
To connect openvpn-auth-oauth2 with openvpn server add lines below:

```conf
# openvpn server.conf
...
# /etc/openvpn/password.txt is a password file where the password must be on first line
management /run/openvpn/server.sock unix /etc/openvpn/password.txt
management-hold
management-client-auth
```

```conf
# openvpn-auth-oauth2 config file
CONFIG_OPENVPN_ADDR=unix:///run/openvpn/server.sock
CONFIG_OPENVPN_PASSWORD=<password>
```

## Setup OIDC Provider

See [Providers](Providers) for more information

## Full configuration example
Configuration openvpn-auth-oauth2 for zitadel

```conf
# Define the public http endpoint here.
CONFIG_HTTP_BASEURL=http://<vpn>:9000/
CONFIG_HTTP_LISTEN=:9000
# Define a random value with 16 or 24 characters
CONFIG_HTTP_SECRET=1jd93h5b6s82lf03jh5b2hf9
CONFIG_OPENVPN_ADDR=unix:///run/openvpn/server.sock
CONFIG_OPENVPN_PASSWORD=<password from /etc/openvpn/password.txt>
CONFIG_OAUTH2_ISSUER=https://company.zitadel.cloud
CONFIG_HTTP_TEMPLATE=/etc/sysconfig/auth.html
CONFIG_OAUTH2_SCOPES=openid profile email offline_access
CONFIG_OAUTH2_CLIENT_ID=34372461928374612@any
CONFIG_OAUTH2_CLIENT_SECRET=ASDhjgadjhAUYSDGjkhasgdIATWDGJHASDtiwGDJAHSGDutwqdygASJKD12hfva
```
