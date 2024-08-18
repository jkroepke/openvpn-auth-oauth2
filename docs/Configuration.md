# Configuration

To configure openvpn-auth-oauth2, the recommended approach uses a YAML file.
If installed through a Linux package,
the file `/etc/sysconfig/openvpn-auth-oauth2` allows configuration of openvpn-auth-oauth2 through environment variables.

## Configuration file

openvpn-auth-oauth2 supports configuration via a YAML file. The file can be passed via the `--config` flag.

<details>
<summary>Example</summary>

```yaml
debug:
  pprof: false
  listen: ":9001"
http:
  assets-path: "" # Example: "/etc/openvpn-auth-oauth2/assets/"
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
  auth-token-user: false
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
  --http.assets-path string
    	Custom path to the assets directory. Files in this directory will be served under /assets/ and having an higher priority than the embedded assets. (env: CONFIG_HTTP_ASSETS__PATH)
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
    	The flag is used to specify a custom OAuth2 authorization endpoint. (env: CONFIG_OAUTH2_ENDPOINT_AUTH)
  --oauth2.endpoint.discovery string
    	The flag is used to set a custom OAuth2 discovery URL. This URL retrieves the provider's configuration details. (env: CONFIG_OAUTH2_ENDPOINT_DISCOVERY)
  --oauth2.endpoint.token string
    	The flag is used to specify a custom OAuth2 token endpoint. (env: CONFIG_OAUTH2_ENDPOINT_TOKEN)
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
    	Override the username of a session with the username from the token by using auth-token-user, if the client username is empty (env: CONFIG_OPENVPN_AUTH__TOKEN__USER) (default true)
  --openvpn.bypass.common-names value
    	bypass oauth authentication for CNs. Comma separated list. (env: CONFIG_OPENVPN_BYPASS_COMMON__NAMES)
  --openvpn.common-name.environment-variable-name string
        Name of the environment variable in the OpenVPN management interface which contains the common name. If username-as-common-name is enabled, this should be set to 'username' to use the username as common name. Other values like 'X509_0_emailAddress' are supported. See https://openvpn.net/community-resources/reference-manual-for-openvpn-2-6/#environmental-variables for more information. (env: CONFIG_OPENVPN_COMMON__NAME_ENVIRONMENT__VARIABLE__NAME) (default "common_name")
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

## Read sensitive data from a file

The following parameter supports sensitive data from the file:

* http.secret
* openvpn.password
* oauth2.client.secret
* oauth2.refresh.secret

To read the sensitive data from the file, use the `file://` prefix, e.g. `file://path/to/secret.txt`.

### openvpn-auth-oauth2 config

openvpn-auth-oauth2 starts an HTTP listener that the OpenVPN client must access before establishing the VPN connection.
By default, the HTTP listener operates on `:9000`.

It is highly recommended to place openvpn-auth-oauth2 behind a reverse proxy terminates the TLS connections.
Configuring `CONFIG_HTTP_BASE_URL` remains crucial because openvpn-auth-oauth2 needs to know the redirect URL.

Example:

<table>
<thead><tr><td>env/sysconfig configuration</td></tr></thead>
<tbody><tr><td>

```ini
# openvpn-auth-oauth2 config file
CONFIG_HTTP_LISTEN=:9000
CONFIG_HTTP_BASE_URL=https://login.example.com
```
</td></tr></tbody>
<thead><tr><td>yaml configuration</td></tr></thead>
<tbody><tr><td>

```yaml
http:
  listen: ":9000"
  baseurl: "https://login.example.com"
```
</td></tr></tbody>
</table>

### Filesystem Permissions

See [Filesystem Permissions](Filesystem%20Permissions) for more information.

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
# The lifetime of the token must be the same as the refresh token in openvpn-auth-oauth2.
# The token can't be extended after it has been generated. The lifetime must be the maximum lifetime of a VPN session.
# 8 hours = 28800 seconds
auth-gen-token 28800 external-auth
```

### openvpn-auth-oauth2 config

<table>
<thead><tr><td>env/sysconfig configuration</td></tr></thead>
<tbody><tr><td>

```ini
# openvpn-auth-oauth2 config file
CONFIG_OPENVPN_ADDR=unix:///run/openvpn/server.sock
CONFIG_OPENVPN_PASSWORD=<password>
```
</td></tr></tbody>
<thead><tr><td>yaml configuration</td></tr></thead>
<tbody><tr><td>

```yaml
openvpn:
  addr: "unix:///run/openvpn/server.sock"
  password: "<password>"
```
</td></tr></tbody>
</table>

## Setup OIDC Provider

See [Providers](Providers) for more information.

## HTTPS Listener

See [HTTPS Listener](HTTPS%20Listener) for more information.

## Custom Login Templates

See [Layout Customization](Layout%20Customization) for more information

## Non-interactive session refresh

See [Non-interactive session refresh](Non-interactive%20session%20refresh) for more information.
