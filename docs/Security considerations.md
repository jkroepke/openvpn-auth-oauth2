# Security Considerations

## Potential Risks Caused by State Reuse

There is a potential risk that an attacker could forge state parameters and hijack an OpenVPN session through phishing attacks. To do this, the attacker would need to know both the state encryption key and the OpenVPN session ID. While the encryption key is a static value, the session ID is a randomly generated incrementing number that changes with each new session.

To mitigate this risk, we recommend the following:
* **Hardening OpenVPN itself**, for example, by introducing `tls-auth`. This requires the attacker to obtain an additional TLS key.
* **Enabling `--http.check.ipaddr`**, which verifies that the IP address of the VPN connection matches that of the HTTP connection.
* **Forcing re-authentication at the SSO provider**, if supported, by setting `--oauth2.authorize-params=prompt=login`. This ensures users must log in again before proceeding.
