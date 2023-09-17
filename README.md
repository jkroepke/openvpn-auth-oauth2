[![CI](https://github.com/jkroepke/openvpn-auth-oauth2/workflows/CI/badge.svg)](https://github.com/jkroepke/openvpn-auth-oauth2/actions?query=workflow%3ACI)
[![GitHub license](https://img.shields.io/github/license/jkroepke/openvpn-auth-oauth2)](https://github.com/jkroepke/openvpn-auth-oauth2/blob/master/LICENSE.txt)

# openvpn-auth-oauth2

STATUS: Beta/Working (Missing documentation)

openvpn-auth-oauth2 is a management client for OpenVPN that handles the authentication
of connecting users against OIDC providers like Azure AD or Keycloak.

## Version requirements

- Server: 2.6.2 or later
- Client: 2.6.0 or later

## Tested environment

### Server

- OpenVPN 2.6.6 on Linux

### Client

#### Working

- [OpenVPN Community Client for Windows 2.6.0](https://openvpn.net/community-downloads/)
- [Tunnelblick](https://tunnelblick.net/) [4.0.0beta10+](https://github.com/Tunnelblick/Tunnelblick/issues/676)

#### Non-Working

- [network-manager-openvpn-gnome](https://gitlab.gnome.org/GNOME/NetworkManager-openvpn) - See https://gitlab.gnome.org/GNOME/NetworkManager-openvpn/-/issues/124

# Installation

Go to https://github.com/jkroepke/openvpn-auth-oauth2/releases/latest and download the binary to the openvpn server.

# Configuration

## Azure AD

### Register an app with AAD

1. Login as admin into tenant
2. Open [App registrations](https://aad.portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/RegisteredApps) in Azure AD admin center
3. Click new registration
4. Pick a name, chose a "Supported account types"-option. Leave the default value, if you are not sure.
5. For redirect uri, choice Web and enter the public endpoint of `openvpn-auth-oauth2`, for example `https://openvpn-auth-oauth2.example.com/oauth2/callback`.
6. Click register.
7. Copy the tenant-id and client-id. You need the both as configuration option for `openvpn-auth-oauth2`.
8. After creation, select `Certificates & secrets` on the left side.
9. Select the tab `Client secrets` and create a new client secret.
10. Copy the client-secret. Need it as configuration option for `openvpn-auth-oauth2`.
11. Then, select Token configuration on the left side.
12. Add optional claim
13. On the right panel, select `ID` as token type
14. Select `ipaddr` from the list of claims.
15. Select Add.

### Configuration

- `--oauth2.issuer https://login.microsoftonline.com/$TENANT_ID/v2.0`
- `--oauth2.client.id $CLIENT_ID`
- `--oauth2.client.secret $CLIENT_SECRET`

References:
- https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app
- https://learn.microsoft.com/en-us/azure/active-directory/develop/active-directory-optional-claims

## Required settings on OpenVPN configuration files

### server.conf

```
# password.txt is a password file where the password must be on first line
management 0.0.0.0 8081 password.txt
management-hold
management-client-auth
```

### client.conf

None

## Supported configuration properties

```
Usage of openvpn-auth-oauth2:
      --configfile string                    path to one .yaml config files. (env: CONFIG_CONFIGFILE)
      --http.baseUrl string                  listen addr for client listener. (env: CONFIG_HTTP_BASEURL) (default "http://localhost:9000")
      --http.callbackTemplatePath string     Path to a HTML file which is displayed at the end of the screen. (env: CONFIG_HTTP_CALLBACKTEMPLATEPATH)
      --http.cert string                     Path to tls server certificate. (env: CONFIG_HTTP_CERT)
      --http.key string                      Path to tls server key. (env: CONFIG_HTTP_KEY)
      --http.listen string                   listen addr for client listener. (env: CONFIG_HTTP_LISTEN) (default ":9000")
      --http.secret string                   Cookie secret. (env: CONFIG_HTTP_SECRET)
      --http.tls                             enable TLS listener. (env: CONFIG_HTTP_TLS)
      --log.format string                    log format. json or console (env: CONFIG_LOG_FORMAT) (default "json")
      --log.level string                     log level. (env: CONFIG_LOG_LEVEL) (default "info")
      --oauth2.bypass.cn strings             bypass oauth authentication for CNs. (env: CONFIG_OAUTH2_BYPASS_CN)
      --oauth2.client.id string              oauth2 client id. (env: CONFIG_OAUTH2_CLIENT_ID)
      --oauth2.client.secret string          oauth2 client secret. (env: CONFIG_OAUTH2_CLIENT_SECRET)
      --oauth2.discoveryUrl string           custom oauth2 discovery url. (env: CONFIG_OAUTH2_DISCOVERY)
      --oauth2.endpoint.authUrl string       custom oauth2 auth endpoint. (env: CONFIG_OAUTH2_ENDPOINT_AUTH_URL)
      --oauth2.endpoint.discovery string     custom oauth2 discovery url. (env: CONFIG_OAUTH2_ENDPOINT_DISCOVERY)
      --oauth2.endpoint.tokenUrl string      custom oauth2 token endpoint. (env: CONFIG_OAUTH2_ENDPOINT_TOKEN_URL)
      --oauth2.issuer string                 oauth2 issuer. (env: CONFIG_OAUTH2_ISSUER)
      --oauth2.scopes strings                oauth2 token scopes. (env: CONFIG_OAUTH2_SCOPES) (default [openid,profile])
      --oauth2.validate.common_name string   validate common_name from OpenVPN with IDToken claim. (env: CONFIG_OAUTH2_VALIDATE_COMMON_NAME)
      --oauth2.validate.groups strings       oauth2 required user groups. (env: CONFIG_OAUTH2_VALIDATE_GROUPS)
      --oauth2.validate.ipaddr               validate client ipaddr between VPN and OIDC token. (env: CONFIG_OAUTH2_VALIDATE_IPADDR)
      --oauth2.validate.issuer               validate issuer from oidc discovery. (env: CONFIG_OAUTH2_VALIDATE_ISSUER) (default true)
      --oauth2.validate.roles strings        oauth2 required user roles. (env: CONFIG_OAUTH2_VALIDATE_ROLES)
      --openvpn.addr string                  openvpn management interface addr. (env: CONFIG_OPENVPN_ADDR) (default "tcp://127.0.0.1:54321")
      --openvpn.password string              openvpn management interface password. (env: CONFIG_OPENVPN_PASSWORD)
```

# Related projects

- https://github.com/CyberNinjas/openvpn-auth-aad
- https://github.com/stilljake/openvpn-oauth2-auth
- https://github.com/jkroepke/openvpn-auth-azure-ad

# Copyright and license

© [2023 Jan-Otto Kröpke (jkroepke)](https://github.com/jkroepke/helm-secrets)

Licensed under the [MIT License](LICENSE.txt)
