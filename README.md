[![CI](https://github.com/jkroepke/openvpn-auth-azure-ad/workflows/CI/badge.svg)](https://github.com/jkroepke/openvpn-auth-azure-ad/actions?query=workflow%3ACI)
[![GitHub license](https://img.shields.io/github/license/jkroepke/openvpn-auth-azure-ad)](https://github.com/jkroepke/openvpn-auth-azure-ad/blob/master/LICENSE.txt)

# openvpn-auth-azure-ad

openvpn-auth-azure-ad is a program that gets executed by openvpn server and handle the authentication
of connecting users against Azure AD.

## Version requirements

Server: 2.6.2 or later
Client: 2.6.0 or later

## Tested environment

### Server

- OpenVPN 2.6.2 on Linux

### Client

#### Working

- [OpenVPN Community Client for Windows 2.6.0](https://openvpn.net/community-downloads/)

#### Non-Working

- [Tunnelblick](https://tunnelblick.net/) - See https://github.com/Tunnelblick/Tunnelblick/issues/676

# Installation

Go to https://github.com/jkroepke/openvpn-auth-azure-ad/releases/latest and download the binary to the openvpn server.

# Configuration

## Register an app with AAD

1. Login as admin into tenant
2. Open [App registrations](https://aad.portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/RegisteredApps) in Azure AD admin center
3. Click new registration
4. Pick a name, chose a "Supported account types"-option. Leave the default value, if you are not sure.
5. Let the redirect uri blank and click register.
6. Copy the tenant-id and client-id. You need the both as configuration option for `openvpn-auth-azure-ad`.
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
# Required
setenv AZURE_AD_TENANT_ID "tenant-id"
setenv AZURE_AD_CLIENT_ID "client-id"

script-security 3
auth-user-pass-verify /usr/local/bin/openvpn-auth-azure-ad via-file
auth-user-pass-optional

# re-authenticate after 86400 seconds. Set 0 for no expiration.
auth-gen-token 86400
```

### client.conf

None

## Supported configuration properties

| Environment Variable                          | Description                                                           | Default                                             |
|-----------------------------------------------|-----------------------------------------------------------------------|-----------------------------------------------------|
| `AZURE_AD_TENANT_ID`                          | Tenant ID off the App Registration                                    | `300`                                               |
| `AZURE_AD_CLIENT_ID`                          | Client ID off the App Registration                                    | `300`                                               |
| `AZURE_AD_TIMEOUT`                            | Time for the user to authenticate in seconds                          | `300`                                               |
| `AZURE_AD_TOKEN_SCOPES`                       | Ask for additional token scopes. Space separated list                 | ``                                                  |
| `AZURE_AD_OPENVPN_URL_HELPER`                 | URL for helping user to initiate the device code login flow.          | `https://jkroepke.github.io/openvpn-auth-azure-ad/` |
| `AZURE_AD_OPENVPN_MATCH_USERNAME_CLIENT_CN`   | Validate, if client common name matches token username.               | `true`                                              |
| `AZURE_AD_OPENVPN_MATCH_USERNAME_TOKEN_FIELD` | Use a custom token field to the common name validation.               | `PreferredUsername`                                 |
| `AZURE_AD_OPENVPN_MATCH_CLIENT_IP`            | Validate, if client ip from OpenVPN and Azure AD login are equal.     | `true`                                              |
| `AZURE_AD_OPENVPN_CN_BYPASS_AZURE_AD`         | Bypass AzureAD authentication for common names. Comma separated list. | ``                                                  |

All environment variables can be set through OpenVPN server configuration with `setenv` directive.

# Related projects

- https://github.com/CyberNinjas/openvpn-auth-aad
- https://github.com/stilljake/openvpn-azure-ad-auth

# Copyright and license

© [2023 Jan-Otto Kröpke (jkroepke)](https://github.com/jkroepke/helm-secrets)

Licensed under the [MIT License](LICENSE.txt)
