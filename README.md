[![CI](https://github.com/jkroepke/openvpn-auth-oauth2/workflows/CI/badge.svg)](https://github.com/jkroepke/openvpn-auth-oauth2/actions?query=workflow%3ACI)
[![GitHub license](https://img.shields.io/github/license/jkroepke/openvpn-auth-oauth2)](https://github.com/jkroepke/openvpn-auth-oauth2/blob/master/LICENSE.txt)

# openvpn-auth-oauth2

openvpn-auth-oauth2 is an executable binary that gets executed by openvpn server via auth-user-pass-verify interace and handles the authentication
of connecting users against OAuth2 endpoints like Azure AD or Keycloak.

## Version requirements

- Server: 2.6.2 or later
- Client: 2.6.0 or later

## Tested environment

### Server

- OpenVPN 2.6.2 on Linux

### Client

#### Working

- [OpenVPN Community Client for Windows 2.6.0](https://openvpn.net/community-downloads/)

#### Non-Working

- [Tunnelblick](https://tunnelblick.net/) - See https://github.com/Tunnelblick/Tunnelblick/issues/676

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

# Required for AzureAD
setenv OAUTH2_PROVIDER "generic"
setenv OAUTH2_GENERIC_ISSUER "https://auth.example.com/realms/openvpn"
setenv OAUTH2_GENERIC_CLIENT_ID "client-id"
setenv OAUTH2_GENERIC_CLIENT_SECRET "client-secret" #optional

# Required for AzureAD
setenv OAUTH2_PROVIDER "azuread"
setenv OAUTH2_AZURE_AD_TENANT_ID "tenant-id"
setenv OAUTH2_AZURE_AD_CLIENT_ID "client-id"

script-security 3
auth-user-pass-verify /usr/local/bin/openvpn-auth-oauth2 via-file
auth-user-pass-optional

# re-authenticate after 86400 seconds. Set 0 for no expiration.
auth-gen-token 86400
```

### client.conf

None

## Supported configuration properties

### Common

| Environment Variable    | Description                                                           | Default                                           |
|-------------------------|-----------------------------------------------------------------------|---------------------------------------------------|
| `OAUTH2_PROVIDER`       | OAuth2 provide. `generic` or `azuread                                 | `generic`                                         |
| `OAUTH2_AUTH_TIMEOUT`   | Time for the user to authenticate in seconds                          | `300`                                             |
| `OAUTH2_URL_HELPER`     | URL for helping user to initiate the device code login flow.          | `https://jkroepke.github.io/openvpn-auth-oauth2/` |
| `OAUTH2_CN_BYPASS_AUTH` | Bypass AzureAD authentication for common names. Comma separated list. | `""`                                                |

### Provider generic

| Environment Variable                        | Description                                             | Default |
|---------------------------------------------|---------------------------------------------------------|---------|
| `OAUTH2_GENERIC_ISSUER`                     | OIDC issuer                                             | -       |
| `OAUTH2_GENERIC_CLIENT_ID`                  | Client ID of the OIDC client                            | -       |
| `OAUTH2_GENERIC_CLIENT_SECRET`              | Client Secret of the OIDC client                        | `""`    |
| `OAUTH2_GENERIC_TOKEN_SCOPES`               | Ask for additional token scopes. Space separated list   | ``      |
| `OAUTH2_GENERIC_MATCH_USERNAME_CLIENT_CN`   | Validate, if client common name matches token username. | `true`  |
| `OAUTH2_GENERIC_MATCH_USERNAME_TOKEN_FIELD` | Use a custom token field to the common name validation. | `sub`   |

### Provider azuread

| Environment Variable                         | Description                                                       | Default                                                          |
|----------------------------------------------|-------------------------------------------------------------------|------------------------------------------------------------------|
| `OAUTH2_AZURE_AD_TENANT_ID`                  | Tenant ID off the App Registration                                | -                                                                |
| `OAUTH2_AZURE_AD_CLIENT_ID`                  | Client ID off the App Registration                                | -                                                                |
| `OAUTH2_AZURE_AD_AUTHORITY`                  | Custom token authority                                            | <details><summary>Show</summary> `https://login.microsoftonline.com/${OAUTH2_AZURE_AD_TENANT_ID}` </details> |
| `OAUTH2_AZURE_AD_TOKEN_SCOPES`               | Ask for additional token scopes. Space separated list             | ``                                                               |
| `OAUTH2_AZURE_AD_MATCH_USERNAME_CLIENT_CN`   | Validate, if client common name matches token username.           | `true`                                                           |
| `OAUTH2_AZURE_AD_MATCH_USERNAME_TOKEN_FIELD` | Use a custom token field to the common name validation.           | `PreferredUsername`                                              |
| `OAUTH2_AZURE_AD_MATCH_CLIENT_IP`            | Validate, if client ip from OpenVPN and Azure AD login are equal. | `true`                                                           |

All environment variables can be set through OpenVPN server configuration with `setenv` directive.

# Related projects

- https://github.com/CyberNinjas/openvpn-auth-aad
- https://github.com/stilljake/openvpn-oauth2-auth
- https://github.com/jkroepke/openvpn-auth-azure-ad

# Copyright and license

© [2023 Jan-Otto Kröpke (jkroepke)](https://github.com/jkroepke/helm-secrets)

Licensed under the [MIT License](LICENSE.txt)
