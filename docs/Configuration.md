# Configuration

The preferred way to configure openvpn-auth-oauth2 is via environment variables. If you install the openvpn-auth-auth2 via
Linux package, use the file `/etc/sysconfig/openvpn-auth-oauth2` to configure openvpn-auth-oauth2.

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

## Configuration file

openvpn-auth-oauth2 supports configuration via a YAML file. The file can be passed via the `--config` flag.

<details>
<summary>Example</summary>

```yaml
debug:
    pprof: false
    listen: :9001
http:
    baseurl: "http://localhost:9000/"
    cert: ""
    check:
        ipaddr: false
    enable-proxy-headers: true
    key: ""
    listen: ":9000"
    # secret: ""
    # template: "" # Path to a HTML file which is displayed at the end of the screen
    tls: false
log:
    format: console
    level: INFO
    vpn-client-ip: true
oauth2:
    authorize-params: "a=c"
    client:
        id: "test"
        secret: "test"
    endpoint:
        # discovery: "https://idp/.well-known/openid-configuration"
        # auth: "https://idp/oauth/auth"
        # token: "https://idp/oauth/token"
    issuer: "https://idp"
    # provider: "generic"
    # scopes:
    #  - "openid"
    #  - "profile"
    validate:
        acr:
        #  - "phr"
        #  - "phrh"
        common-name: ""
        common-name-case-sensitive: false
        # groups:
        #  - "test"
        #  - "test2"
        # roles:
        #   - "test"
        #   - "test2"
        ipaddr: false
        issuer: true
    nonce: true
    pkce: true
    auth-style: "AuthStyleInParams"
    refresh:
        enabled: false
        expires: 8h0m0s
        # secret: ""
        use-session-id: false
        validate-user: true
openvpn:
    addr: "unix:///run/openvpn/server.sock"
    auth-token-user: true
    auth-pending-timeout: 2m
    bypass:
        # common-names:
        # - "test"
        # - "test2"
    common-name:
        environment-variable-name: common_name
        mode: plain
    # password: ""
    pass-through:
        address: "unix:///run/openvpn/pass-through.sock"
        enabled: false
        # password: ""
        # socket-group: ""
        # socket-mode: 660
```
</details>

## Supported configuration properties

<!-- BEGIN USAGE -->
```
Usage of openvpn-auth-oauth2:

  --config string
    	path to one .yaml config file (env: CONFIG_CONFIG)
  --debug.listen string
    	listen address for go profiling endpoint (env: CONFIG_DEBUG_LISTEN) (default ":9001")
  --debug.pprof
    	Enables go profiling endpoint. This should be never exposed. (env: CONFIG_DEBUG_PPROF)
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
    	Random generated secret for cookie encryption. Must be 16, 24 or 32 characters. If argument starts with file:// it reads the secret from a file. (env: CONFIG_HTTP_SECRET)
  --http.template string
    	Path to a HTML file which is displayed at the end of the screen (env: CONFIG_HTTP_TEMPLATE)
  --http.tls
    	enable TLS listener (env: CONFIG_HTTP_TLS)
  --log.format string
    	log format. json or console (env: CONFIG_LOG_FORMAT) (default "console")
  --log.level value
    	log level (env: CONFIG_LOG_LEVEL) (default INFO)
  --log.vpn-client-ip
    	log IP of VPN client. Useful to have an identifier between OpenVPN and openvpn-auth-oauth2. (env: CONFIG_LOG_VPN__CLIENT__IP) (default true)
  --oauth2.auth-style value
    	Auth style represents how requests for tokens are authenticated to the server. Possible values: AuthStyleAutoDetect, AuthStyleInParams, AuthStyleInHeader. See https://pkg.go.dev/golang.org/x/oauth2#AuthStyle (env: CONFIG_OAUTH2_AUTH__STYLE) (default AuthStyleInParams)
  --oauth2.authorize-params string
    	additional url query parameter to authorize endpoint (env: CONFIG_OAUTH2_AUTHORIZE__PARAMS)
  --oauth2.client.id string
    	oauth2 client id (env: CONFIG_OAUTH2_CLIENT_ID)
  --oauth2.client.secret value
    	oauth2 client secret. If argument starts with file:// it reads the secret from a file. (env: CONFIG_OAUTH2_CLIENT_SECRET)
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
    	Required, if oauth2.refresh.enabled=true. Random generated secret for token encryption. Must be 16, 24 or 32 characters. If argument starts with file:// it reads the secret from a file. (env: CONFIG_OAUTH2_REFRESH_SECRET)
  --oauth2.refresh.use-session-id
    	If true, openvpn-auth-oauth2 will use the session_id to refresh sessions on initial auth. Requires 'auth-token-gen [lifetime] external-auth' on OpenVPN server. (env: CONFIG_OAUTH2_REFRESH_USE__SESSION__ID)
  --oauth2.refresh.validate-user
    	If true, openvpn-auth-oauth2 will validate the user against the OIDC provider on each refresh. Usefully, if API limits are exceeded or OIDC provider can't deliver an refresh token. (env: CONFIG_OAUTH2_REFRESH_VALIDATE__USER) (default true)
  --oauth2.scopes value
    	oauth2 token scopes. Defaults depends on oauth2.provider. Comma separated list. Example: openid,profile,email (env: CONFIG_OAUTH2_SCOPES)
  --oauth2.validate.acr value
    	oauth2 required acr values. Comma separated list. Example: phr,phrh (env: CONFIG_OAUTH2_VALIDATE_ACR)
  --oauth2.validate.common-name string
    	validate common_name from OpenVPN with IDToken claim. For example: preferred_username or sub (env: CONFIG_OAUTH2_VALIDATE_COMMON__NAME)
  --oauth2.validate.common-name-case-sensitive
    	If true, openvpn-auth-oauth2 will validate the common case in sensitive mode (env: CONFIG_OAUTH2_VALIDATE_COMMON__NAME__CASE__SENSITIVE)
  --oauth2.validate.groups value
    	oauth2 required user groups. If multiple groups are configured, the user needs to be least in one group. Comma separated list. Example: group1,group2,group3 (env: CONFIG_OAUTH2_VALIDATE_GROUPS)
  --oauth2.validate.ipaddr
    	validate client ipaddr between VPN and oidc token (env: CONFIG_OAUTH2_VALIDATE_IPADDR)
  --oauth2.validate.issuer
    	validate issuer from oidc discovery (env: CONFIG_OAUTH2_VALIDATE_ISSUER) (default true)
  --oauth2.validate.roles value
    	oauth2 required user roles. If multiple role are configured, the user needs to be least in one role. Comma separated list. Example: role1,role2,role3 (env: CONFIG_OAUTH2_VALIDATE_ROLES)
  --openvpn.addr string
    	openvpn management interface addr. Must start with unix:// or tcp:// (env: CONFIG_OPENVPN_ADDR) (default "unix:/run/openvpn/server.sock")
  --openvpn.auth-pending-timeout duration
    	How long OpenVPN server wait until user is authenticated (env: CONFIG_OPENVPN_AUTH__PENDING__TIMEOUT) (default 3m0s)
  --openvpn.auth-token-user
    	Define auth-token-user for all sessions (env: CONFIG_OPENVPN_AUTH__TOKEN__USER) (default true)
  --openvpn.bypass.common-names value
    	bypass oauth authentication for CNs. Comma separated list. (env: CONFIG_OPENVPN_BYPASS_COMMON__NAMES)
  --openvpn.common-name.environment-variable string
    	Name of the environment variable in the OpenVPN management interface which contains the common name. If username-as-common-name is enabled, this should be set to 'username' to use the username as common name. Other values like 'X509_0_emailAddress' are supported. See https://openvpn.net/community-resources/reference-manual-for-openvpn-2-6/#environmental-variables for more information. (env: CONFIG_OPENVPN_COMMON__NAME_ENVIRONMENT__VARIABLE) (default "common_name")
  --openvpn.common-name.mode value
    	If common names are too long, use md5/sha1 to hash them or omit to skip them. If omit, oauth2.validate.common-name does not work anymore. Values: [plain,omit] (env: CONFIG_OPENVPN_COMMON__NAME_MODE) (default plain)
  --openvpn.pass-through.address string
    	The address of the pass-through socket. Must start with unix:// or tcp:// (env: CONFIG_OPENVPN_PASS__THROUGH_ADDRESS) (default "unix:/run/openvpn-auth-oauth2/server.sock")
  --openvpn.pass-through.enabled
    	If true, openvpn-auth-oauth2 will setup a pass-through socket for the OpenVPN management interface.  (env: CONFIG_OPENVPN_PASS__THROUGH_ENABLED)
  --openvpn.pass-through.password value
    	The password for the pass-through socket. If argument starts with file:// it reads the secret from a file. (env: CONFIG_OPENVPN_PASS__THROUGH_PASSWORD)
  --openvpn.pass-through.socket-group string
    	The group for the pass-through socket. Used only, if openvpn.pass-through.address starts with unix:// If empty, the group of the process is used. (env: CONFIG_OPENVPN_PASS__THROUGH_SOCKET__GROUP)
  --openvpn.pass-through.socket-mode uint
    	The unix file permission mode for the pass-through socket. Used only, if openvpn.pass-through.address starts with unix:// (env: CONFIG_OPENVPN_PASS__THROUGH_SOCKET__MODE) (default 660)
  --openvpn.password value
    	openvpn management interface password. If argument starts with file:// it reads the secret from a file. (env: CONFIG_OPENVPN_PASSWORD)
  --version
    	show version
```
<!-- END USAGE -->

## Read sensitive data from file

The following parameter supports sensitive data from the file:

* http.secret
* openvpn.password
* oauth2.client.secret
* oauth2.refresh.secret

To read the sensitive data from the file, use the `file://` prefix, e.g. `file://path/to/secret.txt`.

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

### Filesystem Permissions

When started by systemd, openvpn runs with a [dynamic arbitrary UID](https://0pointer.net/blog/dynamic-users-with-systemd.html).
This means that it may not have access to certain files and directories if the appropriate permissions are not set.

Any additional files, such as TLS keys, should be placed under the `/etc/openvpn-auth-oauth2/` directory.
The owner of these files should be `root` and the group should be `openvpn-auth-oauth2`.
This ensures that openvpn has the necessary permissions to access and use these files.

When installing the openvpn-auth-oauth2 Linux package,
it will automatically handle the creation of the openvpn-auth-oauth2 system group.
This group is used to manage access to the necessary files and directories
and should be used to manage the permissions of any additional files.

## Setup OpenVPN server

To connect openvpn-auth-oauth2 with openvpn server, add lines below:

```ini
# openvpn server.conf
...
# /etc/openvpn/password.txt is a password file where the password must be on first line
management /run/openvpn/server.sock unix /etc/openvpn/password.txt
management-client-auth
# management-hold holds the OpenVPN server until openvpn-auth-oauth2 has been connected.
# In some situation, there is a deadlock where systemd waits for OpenVPN server, not starting
#management-hold

# If auth-user-pass-optional is not set, the OpenVPN server requires username/password from clients
# and terminate the connection with an TLS error, if the client does not provide it.
auth-user-pass-optional

# Enable auth-token-gen to allow non-interactive session refresh
# Mandatory for mobile devices, because auth-token works across disconnects
# The lifetime of the token must be the same as the refresh token in openvpn-auth-oauth2
# 8 hours = 28800 seconds
auth-gen-token 28800 external-auth
```

```ini
# openvpn-auth-oauth2 config file
CONFIG_OPENVPN_ADDR=unix:///run/openvpn/server.sock
CONFIG_OPENVPN_PASSWORD=<password>
```

## Setup OIDC Provider

See [Providers](Providers) for more information

## HTTPS Listener

> [!IMPORTANT]
> Remember to set `CONFIG_HTTP_BASEURL` correctly. It should start with `https://` following your public domain name plus port.

Some SSO Provider like Entra ID requires `https://` based redirect URL.
In the default configuration, openvpn-auth-oauth2 listen on `http://`.
There are two common ways to set up an HTTPS listener

### Reverse proxy (nginx, traefik)

You can use one of your favorite http reverse proxies.
Configure HTTPS on reverse proxy and proxy to an HTTP instance of openvpn-auth-oauth2.
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

You can also use [Let's Encrypt](https://letsencrypt.org/) to get public SSL certificates for free.
The [certbot](https://certbot.eff.org/instructions) is a recommended tool to get SSL certificates.
Alternatively,
you can use [acme.sh](https://acme.sh/), which is a pure Unix shell script implementing ACME client protocol.

openvpn-auth-oauth2 requires a [`SIGHUP` signal](https://en.wikipedia.org/wiki/SIGHUP) to reload the TLS certificate.

## Non-interactive session refresh

By default, `openvpn-auth-oauth2` doesn't store user tokens.
This means users must log in interactively each time they authenticate, including during TLS soft-resets
(triggered by `reneg-sec`).

However, you can change this behavior by enabling the `oauth2.refresh.enabled=true` setting.
This allows `openvpn-auth-oauth2` to store either the connection ID or SessionID (`oauth2.refresh.use-session-id=true`),
accepting connections without additional login checks.

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

### Non-interactive session refresh across disconnects

To facilitate non-interactive session refresh across disconnects,
you must enable `auth-token-gen [lifetime] external-auth` on the OpenVPN server.

- `[lifetime]` represents the duration of the token in seconds.
  Once generated, the token's lifetime cannot be extended.
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

```ini
CONFIG_OAUTH2_REFRESH_ENABLED=true
CONFIG_OAUTH2_REFRESH_EXPIRES=8h
CONFIG_OAUTH2_REFRESH_SECRET= # a static secret to encrypt token. Must be 16, 24 or 32
CONFIG_OAUTH2_REFRESH_USE__SESSION__ID=true
CONFIG_OPENVPN_AUTH__TOKEN__USER=true
```

## username-as-common-name

When configuring `username-as-common-name` on the OpenVPN server,
it's essential to ensure that `openvpn.common-name.environment-variable-name` is also set to `username`.

This configuration is mandatory because `username-as-common-name` operates after the authentication process.
Matching the environment variable name to `username` ensures seamless functionality.

### Note Regarding Passing Usernames from OAuth2 Provider to OpenVPN

It's important to note that currently,
there is no mechanism to pass the username from the OAuth2 provider back to OpenVPN.
OpenVPN does not offer such an interface at present.
This limitation applies to scenarios where the IP persistence file or statistics may contain empty usernames.

For future enhancements in this area,
we encourage users to up-vote the relevant feature requests on the OpenVPN GitHub repository.
You can find and support these requests at the following link:
[Feature Request on GitHub](https://github.com/OpenVPN/openvpn/issues/299)
