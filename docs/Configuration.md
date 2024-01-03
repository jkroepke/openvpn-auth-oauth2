# Configuration

The preferred way to configure openvpn-auth-oauth2 is via environment variables. If you install the openvpn-auth-auth2 via
Linux package, use the file `/etc/sysconfig/openvpn-auth-oauth2` to configure openvpn-auth-oauth2.

## Supported configuration properties

```
Usage of /var/folders/cs/zz5gz_v567v7y00jpvc5v16h0000gn/T/go-build2152924040/b001/exe/main:

  --config string
    	path to one .yaml config file (env: CONFIG_CONFIG)
  --http.baseurl string
    	listen addr for client listener (env: CONFIG_HTTP_BASEURL) (default "http://localhost:9000")
  --http.cert string
    	Path to tls server certificate (env: CONFIG_HTTP_CERT)
  --http.check.ipaddr
    	Check if client IP in http and VPN is equal (env: CONFIG_HTTP_CHECK_IPADDR)
  --http.enable-proxy-headers
    	Use X-Forward-For http header for client ips (env: CONFIG_HTTP_ENABLE__PROXY__HEADERS)
  --http.key string
    	Path to tls server key (env: CONFIG_HTTP_KEY)
  --http.listen string
    	listen addr for client listener (env: CONFIG_HTTP_LISTEN) (default ":9000")
  --http.secret value
    	Cookie secret (env: CONFIG_HTTP_SECRET)
  --http.template string
    	Path to a HTML file which is displayed at the end of the screen (env: CONFIG_HTTP_TEMPLATE)
  --http.tls
    	enable TLS listener (env: CONFIG_HTTP_TLS)
  --log.format string
    	log format. json or console (env: CONFIG_LOG_FORMAT) (default "console")
  --log.level value
    	log level (env: CONFIG_LOG_LEVEL) (default INFO)
  --oauth2.authorize-params string
    	additional url query parameter to authorize endpoint (env: CONFIG_OAUTH2_AUTHORIZE__PARAMS)
  --oauth2.client.id string
    	oauth2 client id (env: CONFIG_OAUTH2_CLIENT_ID)
  --oauth2.client.secret value
    	oauth2 client secret (env: CONFIG_OAUTH2_CLIENT_SECRET)
  --oauth2.endpoint.auth string
    	custom oauth2 auth endpoint (env: CONFIG_OAUTH2_ENDPOINT_AUTH)
  --oauth2.endpoint.discovery string
    	custom oauth2 discovery url (env: CONFIG_OAUTH2_ENDPOINT_DISCOVERY)
  --oauth2.endpoint.token string
    	custom oauth2 token endpoint (env: CONFIG_OAUTH2_ENDPOINT_TOKEN)
  --oauth2.issuer string
    	oauth2 issuer (env: CONFIG_OAUTH2_ISSUER)
  --oauth2.nonce
    	If true, a nonce will be defined on the auth URL which is expected inside the token. (env: CONFIG_OAUTH2_NONCE) (default true)
  --oauth2.pkce
    	If true, Proof Key for Code Exchange (PKCE) RFC 7636 is used for token exchange. (env: CONFIG_OAUTH2_PKCE) (default true)
  --oauth2.provider string
    	oauth2 provider (env: CONFIG_OAUTH2_PROVIDER) (default "generic")
  --oauth2.refresh.enabled
    	If true, openvpn-auth-oauth2 stores refresh tokens and will use it do an non-interaction reauth. (env: CONFIG_OAUTH2_REFRESH_ENABLED)
  --oauth2.refresh.expires duration
    	TTL of stored oauth2 token. (env: CONFIG_OAUTH2_REFRESH_EXPIRES) (default 8h0m0s)
  --oauth2.refresh.secret value
    	Encryption key for stored token in encrypted format. (env: CONFIG_OAUTH2_REFRESH_SECRET)
  --oauth2.scopes value
    	oauth2 token scopes. Defaults depends on oauth2.provider (env: CONFIG_OAUTH2_SCOPES)
  --oauth2.validate.common-name string
    	validate common_name from OpenVPN with IDToken claim (env: CONFIG_OAUTH2_VALIDATE_COMMON__NAME)
  --oauth2.validate.groups value
    	oauth2 required user groups (env: CONFIG_OAUTH2_VALIDATE_GROUPS)
  --oauth2.validate.ipaddr
    	validate client ipaddr between VPN and oidc token (env: CONFIG_OAUTH2_VALIDATE_IPADDR)
  --oauth2.validate.issuer
    	validate issuer from oidc discovery (env: CONFIG_OAUTH2_VALIDATE_ISSUER) (default true)
  --oauth2.validate.roles value
    	oauth2 required user roles (env: CONFIG_OAUTH2_VALIDATE_ROLES)
  --openvpn.addr string
    	openvpn management interface addr. Must start with unix:// or tcp:// (env: CONFIG_OPENVPN_ADDR) (default "unix:/run/openvpn/server.sock")
  --openvpn.auth-pending-timeout duration
    	How long OpenVPN server wait until user is authenticated (env: CONFIG_OPENVPN_AUTH__PENDING__TIMEOUT) (default 3m0s)
  --openvpn.auth-token-user
    	Define auth-token-user for all sessions (env: CONFIG_OPENVPN_AUTH__TOKEN__USER) (default true)
  --openvpn.bypass.cn value
    	bypass oauth authentication for CNs (env: CONFIG_OPENVPN_BYPASS_CN)
  --openvpn.common-name.mode string
    	If common names are too long, use md5/sha1 to hash them or omit to skip them. If omit, oauth2.validate.common-name does not work anymore. Values: [plain,omit] (env: CONFIG_OPENVPN_COMMON__NAME_MODE) (default "plain")
  --openvpn.password value
    	openvpn management interface password (env: CONFIG_OPENVPN_PASSWORD)
  --version
    	show version
```

## Configuration openvpn-auth-oauth2

openvpn-auth-oauth2 starts an HTTP listener which needs to be accessible from the OpenVPN client before the VPN connection is established.
By default, the http listener runs on `:9000`.

It'd highly recommend putting openvpn-auth-oauth2 behind a reverse proxy which terminates the TLS connections.
It's important to configure `CONFIG_HTTP_BASE_URL` because openvpn-auth-oauth2 need to know the redirect url.

Example:

```ini
# openvpn-auth-oauth2 config file
CONFIG_HTTP_LISTEN=:9000
CONFIG_HTTP_BASE_URL=https://login.example.com
```

## Setup OpenVPN server

To connect openvpn-auth-oauth2 with openvpn server, add lines below:

```ini
# openvpn server.conf
...
# /etc/openvpn/password.txt is a password file where the password must be on first line
management /run/openvpn/server.sock unix /etc/openvpn/password.txt
management-hold
management-client-auth
```

```ini
# openvpn-auth-oauth2 config file
CONFIG_OPENVPN_ADDR=unix:///run/openvpn/server.sock
CONFIG_OPENVPN_PASSWORD=<password>
```

## Setup OIDC Provider

See [Providers](Providers) for more information

## Full configuration example

Configuration openvpn-auth-oauth2 for [zitadel](https://zitadel.com/)

```ini
# Define the public http endpoint here.
CONFIG_HTTP_BASEURL=http://<vpn>:9000/
CONFIG_HTTP_LISTEN=:9000
# Define a random value with 16 or 24 characters
CONFIG_HTTP_SECRET=1jd93h5b6s82lf03jh5b2hf9
CONFIG_OPENVPN_ADDR=unix:///run/openvpn/server.sock
CONFIG_OPENVPN_PASSWORD=<password from /etc/openvpn/password.txt>
CONFIG_OAUTH2_ISSUER=https://company.zitadel.cloud
CONFIG_OAUTH2_SCOPES=openid profile email offline_access
CONFIG_OAUTH2_CLIENT_ID=34372461928374612@any
CONFIG_OAUTH2_CLIENT_SECRET=ASDhjgadjhAUYSDGjkhasgdIATWDGJHASDtiwGDJAHSGDutwqdygASJKD12hfva
```

## HTTPS Listener

> [!IMPORTANT]
> Remember to set `CONFIG_HTTP_BASEURL` correctly. It should start with `https://` following your public domain name plus port.

Some SSO Provider like Entra ID requires `https://` based redirect URL.
In the default configuration, openvpn-auth-oauth2 listen on `http://`.
There are two common ways to set up an HTTPS listener

### Reverse proxy (nginx, traefik)

You can use one of your favorite http reverse proxy. Configure HTTPS on reverse proxy and proxy to an HTTP instance of openvpn-auth-oauth2.
For beginners, [traefik](https://traefik.io/traefik/) is recommended since it [natively](https://doc.traefik.io/traefik/https/acme/)
supports [Let's Encrypt](https://letsencrypt.org/) where you can get public SSL certificates for free.

### Using native HTTPS support

openvpn-auth-oauth2 supports HTTPS out of the box.

```ini
CONFIG_HTTP_TLS=true
CONFIG_HTTP_KEY=server.key
CONFIG_HTTP_CERT=server.crt
```

To set up a self-signed certificate, you can use the command below:

```bash
export DOMAIN_NAME=vpn.example.com
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes -keyout server.key -out server.crt -subj "/CN=$DOMAIN_NAME" -addext "subjectAltName=DNS:$DOMAIN_NAME"
```

## Non-interactive session refresh

With default settings, openvpn-auth-oauth2 does not store any tokens from the users. This requires an interactive login from user on
each authentication, included on TLS soft-resets (if `reneg-sec` is triggered).

The interactive login can be avoided by requesting [refresh tokens](https://auth0.com/blog/refresh-tokens-what-are-they-and-when-to-use-them/)
(via oauth2 scope `offline_access`; enabled by default) and store the token inside openvpn-auth-oauth2.

If enabled (via `--oauth2.refresh.enabled=true`), `openvpn-auth-oauth2` will store the oauth2 refresh token in an in-memory key-value store.
`openvpn-auth-oauth2` is using AES to encrypt the tokens.
The token will be bound to the OpenVPN client ID.
While on initially connect the interactive login is still mandatory, `openvpn-auth-oauth2` tries to initiate a non-interactive login with the refresh
token against the OIDC provider and fallbacks to interactive login, if unsuccessful.

References:

- https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow#refresh-the-access-token
- https://curity.io/resources/learn/oauth-refresh/
- https://developer.okta.com/docs/guides/refresh-tokens/main/

```ini
CONFIG_OAUTH2_REFRESH_ENABLED=true
CONFIG_OAUTH2_REFRESH_EXPIRES=8h
```
