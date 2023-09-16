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
5. Let the redirect uri blank and click register.
6. Copy the tenant-id and client-id. You need the both as configuration option for `openvpn-auth-oauth2`.
7. After creation, select Token configuration on the left side.
8. Add optional claim
9. On the right panel, select `ID` as token type
10. Select `ipaddr` from the list of claims.
11. Select Add.

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
      --configfile string                path to one .yaml config files. (env: CONFIG_CONFIGFILE)
      --http.baseurl string              listen addr for client listener. (env: CONFIG_HTTP_BASEURL) (default "http://localhost:9000")
      --http.cert string                 Path to tls server certificate. (env: CONFIG_HTTP_CERT)
      --http.key string                  Path to tls server key. (env: CONFIG_HTTP_KEY)
      --http.listen string               listen addr for client listener. (env: CONFIG_HTTP_LISTEN) (default ":9000")
      --http.sessionsecret string        Secret crypt session tokens. (env: CONFIG_HTTP_SESSIONSECRET)
      --http.tls                         enable TLS listener. (env: CONFIG_HTTP_TLS)
      --oauth2.client.id string          oauth2 client id. (env: CONFIG_OAUTH2_CLIENT_ID)
      --oauth2.client.secret string      oauth2 client secret. (env: CONFIG_OAUTH2_CLIENT_SECRET)
      --oauth2.issuer string             oauth2 issuer. (env: CONFIG_OAUTH2_ISSUER)
      --oauth2.scopes strings            oauth2 token scopes. (env: CONFIG_OAUTH2_SCOPES) (default [openid,offline_access])
      --oauth2.validate.groups strings   oauth2 required user groups. (env: CONFIG_OAUTH2_VALIDATE_GROUPS)
      --oauth2.validate.ipaddr           validate client ipaddr between VPN and OIDC token. (env: CONFIG_OAUTH2_VALIDATE_IPADDR)
      --oauth2.validate.roles strings    oauth2 required user roles. (env: CONFIG_OAUTH2_VALIDATE_ROLES)
      --openvpn.addr string              openvpn management interface addr. (env: CONFIG_OPENVPN_ADDR) (default "127.0.0.1:54321")
      --openvpn.password string          openvpn management interface password. (env: CONFIG_OPENVPN_PASSWORD)
```

# Related projects

- https://github.com/CyberNinjas/openvpn-auth-aad
- https://github.com/stilljake/openvpn-oauth2-auth
- https://github.com/jkroepke/openvpn-auth-azure-ad

# Copyright and license

© [2023 Jan-Otto Kröpke (jkroepke)](https://github.com/jkroepke/helm-secrets)

Licensed under the [MIT License](LICENSE.txt)
