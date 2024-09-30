# OpenVPN

## OpenVPN version requirements

- Server: 2.6.2 or later (OpenVPN Access Server not supported)
- Client: 2.5.0 or later (OpenVPN Client 2.x requires a management client to handle WebAuth, e.g. Viscosity or Tunnelblick)

## Tested environment

### Server

#### Working

- OpenVPN 2.6.6 on Linux

#### Non-Working

- OpenVPN Access Server (any)

### Client

#### Working

- Windows: [OpenVPN Community Client for Windows 2.6.0+](https://openvpn.net/community-downloads/)
- Mac: [Tunnelblick](https://tunnelblick.net/) [4.0.0beta10+](https://github.com/Tunnelblick/Tunnelblick/issues/676)
- Windows/Mac: [Viscosity](https://www.sparklabs.com/viscosity) (**Note:** Visocity denies non-https endpoints by default.)
- Linux: [OpenVPN 3 core library 3.9+](https://github.com/OpenVPN/openvpn3)
- Linux: [openvpn3-indicator](https://github.com/OpenVPN/openvpn3-indicator)

#### Partial Working

- [OpenVPN Connect v3 for Windows/macOS/Linux](https://openvpn.net/vpn-server-resources/connecting-to-access-server-with-macos/) ([workaround](https://github.com/jkroepke/openvpn-auth-oauth2/wiki/Debugging-Errors#error-message-received-control-message-push_request-in-openvpn-client-v3))

#### Non-Working

- [network-manager-openvpn-gnome](https://gitlab.gnome.org/GNOME/NetworkManager-openvpn) -
  See https://gitlab.gnome.org/GNOME/NetworkManager-openvpn/-/issues/124
