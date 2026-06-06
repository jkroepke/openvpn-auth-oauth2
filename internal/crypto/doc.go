// Package crypto provides compact authenticated encryption for values that are
// sent through OpenVPN clients and later accepted back by the server.
//
// The package uses Salsa20 for encryption and HMAC-SHA256 for authentication in
// an encrypt-then-MAC construction. The serialized ciphertext layout is:
//
//	8-byte random nonce || ciphertext || 16-byte truncated HMAC tag
//
// Salsa20 is used because it has a small nonce and does not expand the
// plaintext. The HMAC is verified before decryption with constant-time
// comparison, so modified client-controlled data is rejected before plaintext is
// interpreted. Encryption and authentication keys are derived independently of
// the configured secret with HKDF-SHA256 and different info strings.
//
// EncryptBytesWithTime wraps the encrypted payload with an issued timestamp and
// encodes the result using unpadded URL-safe base64. DecryptBytesWithTime only
// accepts that raw URL-base64 form, rejects oversized input, verifies integrity,
// and rejects data older than two minutes or issued more than five seconds in
// the future.
package crypto
