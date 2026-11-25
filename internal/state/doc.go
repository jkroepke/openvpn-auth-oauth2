// Package state serializes, protects, and restores the OAuth2 state parameter
// used during OpenVPN web authentication.
//
// The state value is sent to the VPN client as part of the authentication URL
// and returns later through the browser callback. The client can see and modify
// that value, so it must be treated as attacker-controlled input. Decrypt
// accepts a state value only after the cryptographic layer has authenticated it,
// which protects the OpenVPN client identifiers, client address, and session
// state from undetected manipulation.
//
// The representation is intentionally compact. The state travels inside the
// "WEB_AUTH::<url>" argument of the client-pending-auth management command,
// and OpenVPN accepts at most 256 characters for a single management parameter
// (OPTION_PARM_SIZE in OpenVPN's options.h). The encrypted state shares that
// budget with the "WEB_AUTH::" prefix, the configured base URL, and the
// callback path. Encrypt therefore uses a versioned binary payload with
// varint client identifiers, flag-controlled optional fields, compact
// session-state codes, binary IP address fields, compact binary forms for
// decimal and hexadecimal strings such as certificate serials, digests and the
// OIDC nonce, a 4-byte issued timestamp,
// unpadded URL-safe base64, and an AES-256-GCM envelope. This keeps the
// parameter inside the OpenVPN management interface constraint while
// preserving integrity and expiry checks for untrusted input.
package state
