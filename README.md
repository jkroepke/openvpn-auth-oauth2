[![CI](https://github.com/jkroepke/openvpn-auth-oauth2/workflows/CI/badge.svg)](https://github.com/jkroepke/openvpn-auth-oauth2/actions?query=workflow%3ACI)
[![GitHub license](https://img.shields.io/github/license/jkroepke/openvpn-auth-oauth2)](https://github.com/jkroepke/openvpn-auth-oauth2/blob/master/LICENSE.txt)
[![Current Release](https://img.shields.io/github/release/jkroepke/openvpn-auth-oauth2.svg)](https://github.com/jkroepke/openvpn-auth-oauth2/releases/latest)
[![GitHub all releases](https://img.shields.io/github/downloads/jkroepke/openvpn-auth-oauth2/total?logo=github)](https://github.com/jkroepke/openvpn-auth-oauth2/releases/latest)
[![Go Report Card](https://goreportcard.com/badge/github.com/jkroepke/openvpn-auth-oauth2)](https://goreportcard.com/report/github.com/jkroepke/openvpn-auth-oauth2)
[![codecov](https://codecov.io/gh/jkroepke/openvpn-auth-oauth2/graph/badge.svg?token=66VT000UYO)](https://codecov.io/gh/jkroepke/openvpn-auth-oauth2)

# openvpn-auth-oauth2

openvpn-auth-oauth2 is a management client for OpenVPN that handles the single sign-on (SSO) authentication
of connecting users against OIDC providers like

* Microsoft Entra ID (Azure AD)
* GitHub
* Okta
* Google Workspace
* Zittal
* Digitalocean
* Keycloak
* ... any other OIDC compatible auth server

## Version requirements

- Server: 2.6.2 or later (OpenVPN Access Server not supported)
- Client: 2.6.0 or later (OpenVPN Client 2.x requires a management client to handle WebAuth, e.g. Viscosity or Tunnelblick)

## Tested environment

### Server

#### Working

- OpenVPN 2.6.6 on Linux

#### Non-Working

- OpenVPN Access Server (any)

### Client

#### Working

- [OpenVPN Community Client for Windows 2.6.0+](https://openvpn.net/community-downloads/)
- [Tunnelblick](https://tunnelblick.net/) [4.0.0beta10+](https://github.com/Tunnelblick/Tunnelblick/issues/676)
- [OpenVPN 3 core library 3.9+](https://github.com/OpenVPN/openvpn3)
- [Viscosity](https://www.sparklabs.com/viscosity)

#### Partial Working

- [OpenVPN Connect v3 for Windows/macOS/Linux] ([workaround](https://github.com/jkroepke/openvpn-auth-oauth2/wiki/Debugging-Errors#error-message-received-control-message-push_request-in-openvpn-client-v3))

#### Non-Working

- [network-manager-openvpn-gnome](https://gitlab.gnome.org/GNOME/NetworkManager-openvpn) -
  See https://gitlab.gnome.org/GNOME/NetworkManager-openvpn/-/issues/124

# Installation

https://github.com/jkroepke/openvpn-auth-oauth2/wiki/Installation

# Configuration

https://github.com/jkroepke/openvpn-auth-oauth2/wiki/Configuration#

# Related projects

- https://github.com/CyberNinjas/openvpn-auth-aad
- https://github.com/vitaliy-sn/openvpn-oidc
- https://github.com/jkroepke/openvpn-auth-azure-ad

# License

[2024 Jan-Otto Kröpke (jkroepke)](https://github.com/jkroepke/openvpn-auth-oauth2)

Licensed under the [MIT License](LICENSE.txt)

# Thanks

<table>
  <thead>
    <tr>
      <th><a href="https://www.jetbrains.com/?from=jkroepke">JetBrains IDEs</a></th>
      <th><a href="https://www.sparklabs.com/viscosity">Sparklabs</a></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><center><a href="https://www.jetbrains.com/?from=jkroepke"><img src="https://resources.jetbrains.com/storage/products/company/brand/logos/jb_beam.svg" alt="JetBrains-Logo (Haupt) logo" height="200px"></a></center></td>
      <td><center><a href="https://www.sparklabs.com/viscosity"><img src="https://www.sparklabs.com/static/other/logo_assets/logo_cropped.png" alt="Sparklabs Viscosity logo" height="200px"></a></center></td>
    </tr>
  </tbody>
</table>




