// Package crypto provides compact authenticated encryption for values that are
// sent through OpenVPN clients and later accepted back by the server.
//
// The package uses XChaCha20-Poly1305 authenticated encryption. The serialized
// ciphertext layout is:
//
//	24-byte random nonce || ciphertext || 16-byte Poly1305 tag
//
// The wide random nonce makes accidental reuse impractical. Authentication is
// verified before plaintext is returned, so modified client-controlled data is
// rejected before it is interpreted. The AEAD key is derived from the configured
// secret with HKDF-SHA256.
//
// EncryptBytesWithTime wraps the encrypted payload with an issued timestamp and
// encodes the result using unpadded URL-safe base64. DecryptBytesWithTime and
// DecryptStringWithTime only accept that raw URL-base64 form, reject oversized
// input, verify integrity, and reject data older than the cipher's configured
// maximum age or issued more than five seconds in the future.
// DecryptStringWithTimeInto lets callers provide reusable destination storage.
package crypto
