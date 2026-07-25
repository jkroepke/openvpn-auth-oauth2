# Configuration

To configure openvpn-auth-oauth2, the recommended approach uses a YAML file.
If installed through a Linux package,
the file `/etc/sysconfig/openvpn-auth-oauth2` allows configuration of openvpn-auth-oauth2 through environment variables.

Take a look at the [FAQ](./FAQ) section, for common questions, issues and solutions.

## Configuration file

openvpn-auth-oauth2 supports configuration via a YAML file. Pass the file with
the `--config` flag or the `OPENVPN_AUTH_OAUTH2_CONFIG_FILE` environment
variable.

See the [example configuration file](https://github.com/jkroepke/openvpn-auth-oauth2/blob/main/packaging/etc/openvpn-auth-oauth2/config.yaml).

## Supported configuration properties

<!-- BEGIN USAGE -->
```
Documentation available at https://github.com/jkroepke/openvpn-auth-oauth2/wiki

Usage of openvpn-auth-oauth2:

  --config string
        path to one .yaml config file (env: OPENVPN_AUTH_OAUTH2_CONFIG_FILE)
  --debug.listen string
        listen address for go profiling endpoint (env: OPENVPN_AUTH_OAUTH2_DEBUG_LISTEN) (default "127.0.0.1:9001")
  --debug.pprof
        Enables go profiling endpoint. This should be never exposed. (env: OPENVPN_AUTH_OAUTH2_DEBUG_PPROF)
  --http.assets-path value
        Custom path to the assets directory. Files in this directory will be served under /assets/ and having an higher priority than the embedded assets. (env: OPENVPN_AUTH_OAUTH2_HTTP_ASSETS__PATH)
  --http.baseurl value
        listen addr for client listener (env: OPENVPN_AUTH_OAUTH2_HTTP_BASEURL) (default http://localhost:9000)
  --http.cert string
        Path to tls server certificate used for TLS listener. (env: OPENVPN_AUTH_OAUTH2_HTTP_CERT)
  --http.check.ipaddr
        Check if client IP in http and VPN is equal (env: OPENVPN_AUTH_OAUTH2_HTTP_CHECK_IPADDR)
  --http.enable-proxy-headers
        Use X-Forwarded-For http header for client ips (env: OPENVPN_AUTH_OAUTH2_HTTP_ENABLE__PROXY__HEADERS)
  --http.trusted-proxies value
        Trusted reverse proxy CIDRs allowed to set X-Forwarded-For. Multiple values can be provided as a comma-separated list. (env: OPENVPN_AUTH_OAUTH2_HTTP_TRUSTED__PROXIES)
  --http.key string
        Path to tls server key used for TLS listener. (env: OPENVPN_AUTH_OAUTH2_HTTP_KEY)
  --http.listen string
        listen addr for client listener (env: OPENVPN_AUTH_OAUTH2_HTTP_LISTEN) (default ":9000")
  --http.secret value
        Random generated secret for cookie encryption. Must be 16, 24 or 32 characters. If argument starts with file:// it reads the secret from a file. (env: OPENVPN_AUTH_OAUTH2_HTTP_SECRET)
  --http.short-url
        Enable short URL. The URL which is used for initial authentication will be reduced to /?s=... instead of /oauth2/start?state=... (env: OPENVPN_AUTH_OAUTH2_HTTP_SHORT__URL)
  --http.template value
        Path to a HTML file which is displayed at the end of the screen. See https://github.com/jkroepke/openvpn-auth-oauth2/wiki/Layout-Customization for more information. (env: OPENVPN_AUTH_OAUTH2_HTTP_TEMPLATE)
  --http.tls
        enable TLS listener (env: OPENVPN_AUTH_OAUTH2_HTTP_TLS)
  --log.format string
        log format. json or console (env: OPENVPN_AUTH_OAUTH2_LOG_FORMAT) (default "console")
  --log.level value
        log level. Can be one of: debug, info, warn, error (env: OPENVPN_AUTH_OAUTH2_LOG_LEVEL) (default INFO)
  --log.vpn-client-ip
        log IP of VPN client. Useful to have an identifier between OpenVPN and openvpn-auth-oauth2. (env: OPENVPN_AUTH_OAUTH2_LOG_VPN__CLIENT__IP) (default true)
  --oauth2.auth-style value
        Auth style represents how requests for tokens are authenticated to the server. Possible values: AuthStyleAutoDetect, AuthStyleInParams, AuthStyleInHeader. See https://pkg.go.dev/golang.org/x/oauth2#AuthStyle (env: OPENVPN_AUTH_OAUTH2_OAUTH2_AUTH__STYLE) (default AuthStyleInParams)
  --oauth2.authorize-params string
        additional url query parameter to authorize endpoint (env: OPENVPN_AUTH_OAUTH2_OAUTH2_AUTHORIZE__PARAMS)
  --oauth2.client.id string
        oauth2 client id (env: OPENVPN_AUTH_OAUTH2_OAUTH2_CLIENT_ID)
  --oauth2.client.private-key value
        oauth2 client private key. Secure alternative to oauth2.client.secret. If argument starts with file:// it reads the secret from a file. (env: OPENVPN_AUTH_OAUTH2_OAUTH2_CLIENT_PRIVATE__KEY)
  --oauth2.client.private-key-id string
        oauth2 client private key id. If specified, JWT assertions will be generated with the specific kid header. (env: OPENVPN_AUTH_OAUTH2_OAUTH2_CLIENT_PRIVATE__KEY__ID)
  --oauth2.client.secret value
        oauth2 client secret. If argument starts with file:// it reads the secret from a file. (env: OPENVPN_AUTH_OAUTH2_OAUTH2_CLIENT_SECRET)
  --oauth2.endpoint.auth value
        The flag is used to specify a custom OAuth2 authorization endpoint. (env: OPENVPN_AUTH_OAUTH2_OAUTH2_ENDPOINT_AUTH)
  --oauth2.endpoint.discovery value
        The flag is used to set a custom OAuth2 discovery URL. This URL retrieves the provider's configuration details. (env: OPENVPN_AUTH_OAUTH2_OAUTH2_ENDPOINT_DISCOVERY)
  --oauth2.endpoint.token value
        The flag is used to specify a custom OAuth2 token endpoint. (env: OPENVPN_AUTH_OAUTH2_OAUTH2_ENDPOINT_TOKEN)
  --oauth2.groups-claim string
        Defines the claim name in the ID Token which contains the user groups. (env: OPENVPN_AUTH_OAUTH2_OAUTH2_GROUPS__CLAIM) (default "groups")
  --oauth2.issuer value
        oauth2 issuer (env: OPENVPN_AUTH_OAUTH2_OAUTH2_ISSUER)
  --oauth2.nonce
        If true, a nonce will be defined on the auth URL which is expected inside the token. (env: OPENVPN_AUTH_OAUTH2_OAUTH2_NONCE) (default true)
  --oauth2.openvpn-username string
        CEL expression to resolve the username from the normalized identity. The expression must evaluate to a string value. Example: string(token.claims.sub). If empty, the common name is used. (env: OPENVPN_AUTH_OAUTH2_OAUTH2_OPENVPN__USERNAME) (default "user.username")
  --oauth2.pkce
        If true, Proof Key for Code Exchange (PKCE) RFC 7636 is used for token exchange. (env: OPENVPN_AUTH_OAUTH2_OAUTH2_PKCE) (default true)
  --oauth2.provider string
        oauth2 provider (env: OPENVPN_AUTH_OAUTH2_OAUTH2_PROVIDER) (default "generic")
  --oauth2.refresh-nonce value
        Controls nonce behavior on refresh token requests. Options: auto (try with nonce, retry without on error), empty (always use empty nonce), equal (use same nonce as initial auth). (env: OPENVPN_AUTH_OAUTH2_OAUTH2_REFRESH__NONCE) (default auto)
  --oauth2.refresh.enabled
        If true, openvpn-auth-oauth2 stores refresh tokens and will use it do an non-interaction reauth. (env: OPENVPN_AUTH_OAUTH2_OAUTH2_REFRESH_ENABLED)
  --oauth2.refresh.expires duration
        TTL of stored oauth2 token. (env: OPENVPN_AUTH_OAUTH2_OAUTH2_REFRESH_EXPIRES) (default 8h0m0s)
  --oauth2.refresh.secret value
        Required, if oauth2.refresh.enabled=true. Random generated secret for token encryption. Must be 16, 24 or 32 characters. If argument starts with file:// it reads the secret from a file. (env: OPENVPN_AUTH_OAUTH2_OAUTH2_REFRESH_SECRET)
  --oauth2.refresh.use-session-id
        If true, openvpn-auth-oauth2 will use the session_id to refresh sessions on initial auth. Requires 'auth-token-gen [lifetime] external-auth' on OpenVPN server. (env: OPENVPN_AUTH_OAUTH2_OAUTH2_REFRESH_USE__SESSION__ID)
  --oauth2.refresh.validate-user
        If true, openvpn-auth-oauth2 will validate the user against the OIDC provider on each refresh. Usefully, if API limits are exceeded or OIDC provider can't deliver an refresh token. (env: OPENVPN_AUTH_OAUTH2_OAUTH2_REFRESH_VALIDATE__USER) (default true)
  --oauth2.scopes value
        oauth2 token scopes. Defaults depends on oauth2.provider. Comma separated list. Example: openid,profile,email (env: OPENVPN_AUTH_OAUTH2_OAUTH2_SCOPES)
  --oauth2.user-info
        If true, openvpn-auth-oauth2 uses the OIDC UserInfo endpoint to fetch additional information about the user (e.g. groups). (env: OPENVPN_AUTH_OAUTH2_OAUTH2_USER__INFO)
  --oauth2.validate.expression string
        CEL expression for custom identity validation. The expression must evaluate to a boolean value. Example: openvpn.commonName == user.username (env: OPENVPN_AUTH_OAUTH2_OAUTH2_VALIDATE_EXPRESSION)
  --oauth2.validate.groups value
        oauth2 required user groups. If multiple groups are configured, the user needs to be least in one group. Comma separated list. Example: group1,group2,group3 (env: OPENVPN_AUTH_OAUTH2_OAUTH2_VALIDATE_GROUPS)
  --openvpn.addr value
        openvpn management interface addr. Must start with unix:// or tcp:// (env: OPENVPN_AUTH_OAUTH2_OPENVPN_ADDR) (default unix:/run/openvpn/server.sock)
  --openvpn.auth-pending-timeout duration
        How long OpenVPN server wait until user is authenticated (env: OPENVPN_AUTH_OAUTH2_OPENVPN_AUTH__PENDING__TIMEOUT) (default 3m0s)
  --openvpn.auth-token-user
        Override the username of a session with the username from the token by using auth-token-user, if the client username is empty (env: OPENVPN_AUTH_OAUTH2_OPENVPN_AUTH__TOKEN__USER) (default true)
  --openvpn.bypass.common-names value
        Skip OAuth authentication for client certificate common names (CNs) matching any of the given regular expressions. Multiple expressions can be provided as a comma-separated list. Regular expressions are automatically anchored (^…$) by default, so "client" matches only "client". To allow partial matches, specify explicitly (e.g. "client.*"). (env: OPENVPN_AUTH_OAUTH2_OPENVPN_BYPASS_COMMON__NAMES)
  --openvpn.client-config.enabled
        If true, openvpn-auth-oauth2 will read the CCD directory for additional configuration. This function mimic the client-config-dir directive in OpenVPN. (env: OPENVPN_AUTH_OAUTH2_OPENVPN_CLIENT__CONFIG_ENABLED)
  --openvpn.client-config.path value
        Path to the CCD directory. openvpn-auth-oauth2 will look for an file with an .conf suffix and returns the content back. (env: OPENVPN_AUTH_OAUTH2_OPENVPN_CLIENT__CONFIG_PATH)
  --openvpn.client-config.ignore-not-found
        Ignore missing client configuration files. (env: OPENVPN_AUTH_OAUTH2_OPENVPN_CLIENT__CONFIG_IGNORE__NOT__FOUND) (default true)
  --openvpn.client-config.expression string
        CEL expression that returns an ordered list of client configuration names. (env: OPENVPN_AUTH_OAUTH2_OPENVPN_CLIENT__CONFIG_EXPRESSION)
  --openvpn.client-config.strategy value
        Client config selection strategy. Values: [merge,user-selector]. (env: OPENVPN_AUTH_OAUTH2_OPENVPN_CLIENT__CONFIG_STRATEGY) (default merge)
  --openvpn.common-name.environment-variable-name string
        Name of the environment variable in the OpenVPN management interface which contains the common name. If username-as-common-name is enabled, this should be set to 'username' to use the username as common name. Other values like 'X509_0_emailAddress' are supported. See https://openvpn.net/community-resources/reference-manual-for-openvpn-2-6/#environmental-variables for more information. (env: OPENVPN_AUTH_OAUTH2_OPENVPN_COMMON__NAME_ENVIRONMENT__VARIABLE__NAME) (default "common_name")
  --openvpn.common-name.mode value
        If common names are too long, use md5/sha1 to hash them or omit to skip them. Values: [plain,omit] (env: OPENVPN_AUTH_OAUTH2_OPENVPN_COMMON__NAME_MODE) (default plain)
  --openvpn.enforce-unique-user
        Requires OpenVPN Server 2.7 and openvpn.override-username=true. If true, openvpn-auth-oauth2 enforces one active OpenVPN session per username. (env: OPENVPN_AUTH_OAUTH2_OPENVPN_ENFORCE__UNIQUE__USER)
  --openvpn.override-username
        Requires OpenVPN Server 2.7! If true, openvpn-auth-oauth2 use the override-username command to set the username in OpenVPN connection. This is useful to use real usernames in OpenVPN statistics. The username will be set after client configs are read. Read OpenVPN man page for limitations of the override-username. (env: OPENVPN_AUTH_OAUTH2_OPENVPN_OVERRIDE__USERNAME)
  --openvpn.pass-through.address value
        The address of the pass-through socket. Must start with unix:// or tcp:// (env: OPENVPN_AUTH_OAUTH2_OPENVPN_PASS__THROUGH_ADDRESS) (default unix:/run/openvpn-auth-oauth2/server.sock)
  --openvpn.pass-through.enabled
        If true, openvpn-auth-oauth2 will setup a pass-through socket for the OpenVPN management interface. (env: OPENVPN_AUTH_OAUTH2_OPENVPN_PASS__THROUGH_ENABLED)
  --openvpn.pass-through.password value
        The password for the pass-through socket. If argument starts with file:// it reads the secret from a file. (env: OPENVPN_AUTH_OAUTH2_OPENVPN_PASS__THROUGH_PASSWORD)
  --openvpn.pass-through.socket-group string
        The group for the pass-through socket. Used only, if openvpn.pass-through.address starts with unix:// If empty, the group of the process is used. (env: OPENVPN_AUTH_OAUTH2_OPENVPN_PASS__THROUGH_SOCKET__GROUP)
  --openvpn.pass-through.socket-mode uint
        The unix file permission mode for the pass-through socket. Used only, if openvpn.pass-through.address starts with unix:// (env: OPENVPN_AUTH_OAUTH2_OPENVPN_PASS__THROUGH_SOCKET__MODE) (default 660)
  --openvpn.password value
        openvpn management interface password. If argument starts with file:// it reads the secret from a file. (env: OPENVPN_AUTH_OAUTH2_OPENVPN_PASSWORD)
  --openvpn.reauthentication
        If set to false, openvpn-auth-oauth2 rejects all re-authentication requests. (env: OPENVPN_AUTH_OAUTH2_OPENVPN_REAUTHENTICATION) (default true)
  --provider.google.validate.groups-transitive
        If true, required group membership for the Google provider is matched transitively: nested sub-groups of a configured group in oauth2.validate.groups are accepted. Requires the cloud-identity.groups.readonly scope and a Google Workspace/Cloud Identity plan that supports the Cloud Identity checkTransitiveMembership API. (env: OPENVPN_AUTH_OAUTH2_PROVIDER_GOOGLE_VALIDATE_GROUPS__TRANSITIVE)
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
Configuring `OPENVPN_AUTH_OAUTH2_HTTP_BASEURL` remains crucial because openvpn-auth-oauth2 needs to know the redirect URL.

Example:

<table>
<thead><tr><td>env/sysconfig configuration</td></tr></thead>
<tbody><tr><td>

```ini
# openvpn-auth-oauth2 config file
OPENVPN_AUTH_OAUTH2_HTTP_LISTEN=:9000
OPENVPN_AUTH_OAUTH2_HTTP_BASEURL=https://login.example.com
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

To connect openvpn-auth-oauth2 with OpenVPN server, add lines below:

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
OPENVPN_AUTH_OAUTH2_OPENVPN_ADDR=unix:///run/openvpn/server.sock
OPENVPN_AUTH_OAUTH2_OPENVPN_PASSWORD=<password>
OPENVPN_AUTH_OAUTH2_OPENVPN_OVERRIDE__USERNAME=true # For OpenVPN 2.7+ servers
```
</td></tr></tbody>
<thead><tr><td>yaml configuration</td></tr></thead>
<tbody><tr><td>

```yaml
openvpn:
  addr: "unix:///run/openvpn/server.sock"
  password: "<password>"
  override-username: true # For OpenVPN 2.7+ servers
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

## Client specific configuration

See [Client specific configuration](Client%20specific%20configuration) for more information.

## OpenVPN username handling

See [OpenVPN Username](OpenVPN%20Username) for more information.
