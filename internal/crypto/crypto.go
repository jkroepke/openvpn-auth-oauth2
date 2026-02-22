package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/salsa20"
)

const salsa20NonceSize = 8
const hmacTagSize = 16

// ErrCipherTextBlockSize is returned when the ciphertext block size is too short
var ErrCipherTextBlockSize = errors.New("ciphertext block size is too short")

// ErrHMACVerificationFailed is returned when HMAC verification fails
var ErrHMACVerificationFailed = errors.New("HMAC verification failed")

// Cipher provides encryption and decryption operations using Salsa20 + HMAC-SHA256
type Cipher struct {
	derivedKey    *[32]byte
	encryptionKey string
}

// New creates a new Cipher instance with the given encryption key.
// The key is derived using SHA256 to ensure consistent key length for Salsa20.
func New(encryptionKey string) *Cipher {
	return &Cipher{
		derivedKey:    DeriveKey(encryptionKey),
		encryptionKey: encryptionKey,
	}
}

// DeriveKey derives a 32-byte key from the input key string using SHA256.
// This ensures consistent key length for Salsa20 regardless of input.
func DeriveKey(key string) *[32]byte {
	hash := sha256.Sum256([]byte(key))
	return &hash
}

// EncryptBytes encrypts data using Salsa20 + HMAC-SHA256 (Encrypt-then-MAC).
// Salsa20 provides stream cipher encryption with minimal overhead (8-byte nonce),
// and HMAC-SHA256 provides authentication and tamper detection.
func (c *Cipher) EncryptBytes(plainText []byte) ([]byte, error) {
	// Generate random nonce
	nonce := make([]byte, salsa20NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt using Salsa20
	cipherText := make([]byte, len(plainText))
	salsa20.XORKeyStream(cipherText, plainText, nonce, c.derivedKey)

	// Calculate HMAC over nonce + ciphertext (Encrypt-then-MAC)
	h := hmac.New(sha256.New, []byte(c.encryptionKey))
	h.Write(nonce)
	h.Write(cipherText)
	tag := h.Sum(nil)[:hmacTagSize] // Use first 16 bytes of HMAC for compact overhead

	// Return: nonce + ciphertext + HMAC tag
	result := make([]byte, 0, len(nonce)+len(cipherText)+len(tag))
	result = append(result, nonce...)
	result = append(result, cipherText...)
	result = append(result, tag...)

	return result, nil
}

// DecryptBytesBase64 decrypts data encrypted with EncryptBytes.
// Verifies HMAC-SHA256 tag before decryption to ensure data integrity (Encrypt-then-MAC).
func (c *Cipher) DecryptBytesBase64(encryptedData []byte) ([]byte, error) {
	// Minimum size: nonce (8) + ciphertext (at least 1) + HMAC tag (16)
	if len(encryptedData) < salsa20NonceSize+1+hmacTagSize {
		return nil, ErrCipherTextBlockSize
	}

	// Extract components
	nonce := encryptedData[:salsa20NonceSize]
	cipherText := encryptedData[salsa20NonceSize : len(encryptedData)-hmacTagSize]
	tag := encryptedData[len(encryptedData)-hmacTagSize:]

	// Verify HMAC before decryption (constant-time comparison)
	h := hmac.New(sha256.New, []byte(c.encryptionKey))
	h.Write(nonce)
	h.Write(cipherText)
	expectedTag := h.Sum(nil)[:hmacTagSize]

	if !hmac.Equal(tag, expectedTag) {
		return nil, ErrHMACVerificationFailed
	}

	// Decrypt using Salsa20
	plainText := make([]byte, len(cipherText))
	salsa20.XORKeyStream(plainText, cipherText, nonce, c.derivedKey)

	return plainText, nil
}
