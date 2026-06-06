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
// The representation is intentionally compact. OpenVPN documents the WEB_AUTH
// control message as space constrained and recommends using short URLs; this
// project also enforces a conservative 245-character limit for the full
// authentication URL passed to client-pending-auth. The encrypted state must
// share that budget with the configured base URL and callback path. Encrypt
// therefore uses a versioned binary payload with varint client identifiers,
// flag-controlled optional fields, compact session-state codes, binary IP
// address fields, unpadded URL-safe base64, and a low-overhead Salsa20 plus
// HMAC envelope. The extra complexity keeps the value inside the OpenVPN URL
// constraints while preserving integrity and expiry checks for untrusted input.
package state
