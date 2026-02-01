# Home

Welcome to the openvpn-auth-oauth2 wiki!

# OpenVPN version requirements

1. [OpenVPN requirements](OpenVPN)
2. [Installation](Installation)
3. [Configuration](Configuration)
4. [Providers](Providers)
5. [Client token validation](Client%20token%20validation)
6. [FAQ](FAQ)

You can find a demo of the plugin in action [here](Demo)

# Flow

```mermaid
sequenceDiagram
    OpenVPN Client->>+OpenVPN Server: connect
    OpenVPN Server->>+openvpn-auth-oauth2: ">CLIENT:CONNECT"
    openvpn-auth-oauth2-->>-OpenVPN Server: "WEBAUTH:https://openvpn.example.com"
    OpenVPN Server-->>-OpenVPN Client: "WEBAUTH:https://openvpn.example.com"

    Note over OpenVPN Client,Browser: The OpenVPN client opens a browser on the machine
    Browser->>+openvpn-auth-oauth2: connect https://openvpn.example.com
    openvpn-auth-oauth2->>+OAuth2 Provider: redirects
    actor User
    Note over OAuth2 Provider,User: User enter credentials
    OAuth2 Provider-->>-openvpn-auth-oauth2: Login Successful
    Note over openvpn-auth-oauth2: Store refresh token, if provided
    openvpn-auth-oauth2-->>-Browser: Login Successful
    openvpn-auth-oauth2->>OpenVPN Server: client-auth

    Note over OpenVPN Client,OpenVPN Server: connection established
    OpenVPN Client->>+OpenVPN Server: Session refresh (reneg-sec)
    OpenVPN Server->>+openvpn-auth-oauth2: ">CLIENT:REAUTH"
    alt has refresh token
    openvpn-auth-oauth2->>+OAuth2 Provider: "Non-interactive login via refresh token"
    OAuth2 Provider-->>-openvpn-auth-oauth2: Login Successful
    else has no refresh token
    Note over openvpn-auth-oauth2,OAuth2 Provider: Traditional login, see above
    end
    Note over openvpn-auth-oauth2: Store new refresh token, if provided
    openvpn-auth-oauth2->>OpenVPN Server: client-auth
    Note over OpenVPN Client,OpenVPN Server: connection refreshed
```
