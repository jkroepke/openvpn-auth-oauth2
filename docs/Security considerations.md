# Security Considerations

## Encryption of Sensitive Data

openvpn-auth-oauth2 uses **Salsa20 stream cipher with HMAC-SHA256 authentication** to encrypt:
- OAuth2 refresh tokens (when enabled)
- State parameters in authentication flows
- User session information

This approach provides:
- ✅ **Confidentiality**: Strong encryption with stream cipher
- ✅ **Integrity**: HMAC-SHA256 detects any tampering
- ✅ **Authentication**: Verifies data wasn't modified by attackers
- ✅ **Minimal overhead**: Only 24 bytes extra per encrypted message

For technical details, see the [Encryption and Cryptography documentation](./Encryption%20and%20Cryptography.md).

## Potential Risks Caused by State Reuse

There is a potential risk that an attacker could forge state parameters and hijack an OpenVPN session through phishing attacks. To do this, the attacker would need to know both the state encryption key, and the OpenVPN session ID. While the encryption key is a static value, the session ID is a randomly generated incrementing number that changes with each new session.

To mitigate this risk, we recommend the following:
* **Hardening OpenVPN itself**, for example, by introducing `tls-auth`. This requires the attacker to obtain an additional TLS key.
* **Enabling `--http.check.ipaddr`**, which verifies that the IP address of the VPN connection matches that of the HTTP connection.
* **Forcing re-authentication at the SSO provider**, if supported, by setting `--oauth2.authorize-params=prompt=login`. This ensures users must log in again before proceeding.

## Social Engineering Attacks via OIDC Login Links

An attacker could initiate a VPN connection on their own device and then send the generated OIDC login link to an unsuspecting employee via phishing (e.g., email, instant messaging, or SMS). If the employee clicks the link and completes the authentication, the attacker’s VPN session would be authenticated using the employee’s credentials, granting unauthorized access to the network.

### Attack Scenario

1. The attacker initiates an OpenVPN connection from their device
2. openvpn-auth-oauth2 generates an authentication URL for this connection attempt
3. The attacker sends this URL to a target employee (via phishing email, SMS, etc.)
4. The employee clicks the link and authenticates with their credentials
5. The attackers VPN session is now authenticated as the employee, gaining access to the network.

### Mitigations

To protect against this type of social engineering attack, consider implementing the following measures:

* **Enable IP address validation with `--http.check.ipaddr`**: This ensures that the IP address initiating the VPN connection matches the IP address completing the OIDC authentication flow. This is the most effective technical control, as it prevents the attack even if the employee clicks the link, since the authentication will be rejected due to the IP mismatch.
  > [!NOTE]
  > While `--http.check.ipaddr` provides strong technical protection against this attack vector, it may not be suitable for all environments (e.g., users behind NAT, mobile users with changing IPs, or organizations using forward proxies). In such cases, compensating controls like user education and enhanced monitoring become even more critical.


* **Implement additional authentication context verification**: Consider using OIDC features that provide additional context:
  * Use `--oauth2.authorize-params` to request additional claims that can be validated
  * Require multifactor authentication (MFA) at the OIDC provider level

* **Session binding improvements**:
  * Use short authentication timeouts (`--openvpn.auth-pending-timeout`) to reduce the window of opportunity for attacker’s
  * Consider implementing additional session binding mechanisms beyond IP addresses, if your environment supports it.
