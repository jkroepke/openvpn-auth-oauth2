[![CI](https://github.com/jkroepke/openvpn-auth-oauth2/workflows/CI/badge.svg)](https://github.com/jkroepke/openvpn-auth-oauth2/actions?query=workflow%3ACI)
[![GitHub license](https://img.shields.io/github/license/jkroepke/openvpn-auth-oauth2)](https://github.com/jkroepke/openvpn-auth-oauth2/blob/master/LICENSE.txt)
[![Current Release](https://img.shields.io/github/release/jkroepke/openvpn-auth-oauth2.svg)](https://github.com/jkroepke/openvpn-auth-oauth2/releases/latest)
[![GitHub all releases](https://img.shields.io/github/downloads/jkroepke/openvpn-auth-oauth2/total?logo=github)](https://github.com/jkroepke/openvpn-auth-oauth2/releases/latest)
[![codecov](https://codecov.io/gh/jkroepke/openvpn-auth-oauth2/graph/badge.svg?token=66VT000UYO)](https://codecov.io/gh/jkroepke/openvpn-auth-oauth2)

# openvpn-auth-oauth2

openvpn-auth-oauth2 is a management client for OpenVPN that handles the authentication
of connecting users against OIDC providers like Azure AD, GitHub or Keycloak.

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
- OpenVPN 3 on Linux (Issue: Browser does no open on REAUTH)

#### Non-Working

- [network-manager-openvpn-gnome](https://gitlab.gnome.org/GNOME/NetworkManager-openvpn) - See https://gitlab.gnome.org/GNOME/NetworkManager-openvpn/-/issues/124

# Installation

https://github.com/jkroepke/openvpn-auth-oauth2/wiki/Installation

# Configuration

https://github.com/jkroepke/openvpn-auth-oauth2/wiki/Configuration

# Related projects

- https://github.com/CyberNinjas/openvpn-auth-aad
- https://github.com/vitaliy-sn/openvpn-oidc
- https://github.com/jkroepke/openvpn-auth-azure-ad

# Copyright and license

© [2023 Jan-Otto Kröpke (jkroepke)](https://github.com/jkroepke/openvpn-auth-oauth2)

Licensed under the [MIT License](LICENSE.txt)
