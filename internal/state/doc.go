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
// The representation is intentionally compact. OpenVPN accepts at most 1023
// bytes for the complete client-pending-auth management command. The encrypted
// state shares that budget with command metadata, the configured base URL, and
// the callback path. Encrypt therefore uses a versioned binary payload with
// varint client identifiers, flag-controlled optional fields, compact
// session-state codes, binary IP address fields, unpadded URL-safe base64, and
// an AES-256-GCM envelope. This keeps the command inside the OpenVPN
// management interface constraint while preserving integrity and expiry checks
// for untrusted input.
package state
