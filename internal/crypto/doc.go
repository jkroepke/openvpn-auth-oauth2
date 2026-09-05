// Package crypto provides compact authenticated encryption for values that are
// sent through OpenVPN clients and later accepted back by the server.
//
// The package uses AES-256-GCM authenticated encryption. The serialized
// ciphertext layout is:
//
//	12-byte random nonce || ciphertext || 16-byte GCM tag
//
// Go generates and prepends a fresh random nonce for each encryption.
// Authentication is verified before plaintext is returned, so modified
// client-controlled data is rejected before it is interpreted. The AEAD key is
// derived from the configured secret with HKDF-SHA256.
//
// EncryptBytesWithTime wraps the encrypted payload with an issued timestamp and
// encodes the result using unpadded URL-safe base64. DecryptBytesWithTime and
// DecryptStringWithTime only accept that raw URL-base64 form, reject oversized
// input, verify integrity, and reject data older than the cipher's configured
// maximum age or issued more than five seconds in the future.
// DecryptStringWithTimeInto lets callers provide reusable destination storage.
package crypto
