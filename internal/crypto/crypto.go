package crypto

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"golang.org/x/crypto/salsa20"
)

const (
	salsa20NonceSize = 8
	hmacTagSize      = 16
	derivedKeySize   = 32
)

// ErrCipherTextBlockSize is returned when the ciphertext block size is too short.
var ErrCipherTextBlockSize = errors.New("ciphertext block size is too short")

// ErrHMACVerificationFailed is returned when HMAC verification fails.
var ErrHMACVerificationFailed = errors.New("hmac verification failed")

// Cipher provides encryption and decryption operations using Salsa20 + HMAC-SHA256.
type Cipher struct {
	encKey *[32]byte // HKDF-derived key for Salsa20 encryption
	macKey []byte    // HKDF-derived key for HMAC-SHA256 authentication
}

// New creates a new Cipher instance with the given encryption key.
// Both the encryption key and the MAC key are independently derived from the
// input using HKDF-SHA256 with distinct info strings ("salsa20-encryption" and
// "hmac-authentication") to ensure domain separation. The raw key string is not
// retained in memory after construction.
func New(encryptionKey string) *Cipher {
	secret := []byte(encryptionKey)

	encKeyBytes := deriveHKDFKey(secret, "salsa20-encryption")
	macKeyBytes := deriveHKDFKey(secret, "hmac-authentication")

	var encKey [32]byte
	copy(encKey[:], encKeyBytes)

	return &Cipher{
		encKey: &encKey,
		macKey: macKeyBytes,
	}
}

// DeriveKey derives a 32-byte key from the input key string using HKDF-SHA256
// with the "salsa20-encryption" info string.
func DeriveKey(key string) *[32]byte {
	b := deriveHKDFKey([]byte(key), "salsa20-encryption")

	var result [32]byte
	copy(result[:], b)

	return &result
}

// deriveHKDFKey derives a 32-byte key using HKDF-SHA256 with the given secret and info string.
func deriveHKDFKey(secret []byte, info string) []byte {
	key, err := hkdf.Key(sha256.New, secret, nil, info, derivedKeySize)
	if err != nil {
		// hkdf.Key only errors when keyLength > 255*hashLen (where hashLen=32 for SHA-256); 32 bytes is always safe.
		panic(fmt.Sprintf("hkdf.Key: unexpected error: %v", err))
	}

	return key
}

// EncryptBytes encrypts data using Salsa20 + HMAC-SHA256 (Encrypt-then-MAC).
// Salsa20 provides stream cipher encryption with minimal overhead (8-byte nonce),
// and HMAC-SHA256 provides authentication and tamper detection.
func (c *Cipher) EncryptBytes(plainText []byte) ([]byte, error) {
	// Generate random nonce
	nonce := make([]byte, salsa20NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt using Salsa20
	cipherText := make([]byte, len(plainText))
	salsa20.XORKeyStream(cipherText, plainText, nonce, c.encKey)

	// Calculate HMAC over nonce + ciphertext (Encrypt-then-MAC)
	h := hmac.New(sha256.New, c.macKey)
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

// DecryptBytes decrypts data encrypted with EncryptBytes.
// Verifies HMAC-SHA256 tag before decryption to ensure data integrity (Encrypt-then-MAC).
func (c *Cipher) DecryptBytes(encryptedData []byte) ([]byte, error) {
	// Minimum size: nonce (8) + optional ciphertext (0+) + HMAC tag (16)
	if len(encryptedData) < salsa20NonceSize+hmacTagSize {
		return nil, ErrCipherTextBlockSize
	}

	// Extract components
	nonce := encryptedData[:salsa20NonceSize]
	cipherText := encryptedData[salsa20NonceSize : len(encryptedData)-hmacTagSize]
	tag := encryptedData[len(encryptedData)-hmacTagSize:]

	// Verify HMAC before decryption (constant-time comparison)
	h := hmac.New(sha256.New, c.macKey)
	h.Write(nonce)
	h.Write(cipherText)
	expectedTag := h.Sum(nil)[:hmacTagSize]

	if !hmac.Equal(tag, expectedTag) {
		return nil, ErrHMACVerificationFailed
	}

	// Decrypt using Salsa20
	plainText := make([]byte, len(cipherText))
	salsa20.XORKeyStream(plainText, cipherText, nonce, c.encKey)

	return plainText, nil
}

func (c *Cipher) EncryptBytesWithTime(plainText []byte) ([]byte, error) {
	issued := time.Now().Round(time.Second).Unix()
	plainText = append([]byte(strconv.FormatInt(issued, 10)+" "), plainText...)

	encrypted, err := c.EncryptBytes(plainText)
	if err != nil {
		return nil, err
	}

	encryptedBase64 := make([]byte, base64.URLEncoding.EncodedLen(len(encrypted)))

	base64.URLEncoding.Encode(encryptedBase64, encrypted)

	return encryptedBase64, nil
}

func (c *Cipher) DecryptBytesWithTime(encryptedBase64 []byte) ([]byte, error) {
	if err := checkTokenSize(encryptedBase64); err != nil {
		return nil, err
	}

	encrypted := make([]byte, base64.URLEncoding.DecodedLen(len(encryptedBase64)))

	n, err := base64.URLEncoding.Decode(encrypted, encryptedBase64)
	if err != nil {
		return nil, fmt.Errorf("base64 decode %q: %w", encryptedBase64, err)
	}

	data, err := c.DecryptBytes(encrypted[:n])
	if err != nil {
		return nil, err
	}

	issued, data, err := extractIssued(data)
	if err != nil {
		return nil, err
	}

	if err := validateIssued(issued); err != nil {
		return nil, err
	}

	return data, nil
}

// Helper to check token size.
func checkTokenSize(encodedState []byte) error {
	if len(encodedState) > 4096 {
		return fmt.Errorf("%w: token too large", ErrInvalid)
	}

	return nil
}

// extractIssued extracts the issued timestamp from the decrypted data.
// The timestamp is stored as a string followed by a space at the beginning of the data.
func extractIssued(data []byte) (int64, []byte, error) {
	// Find the space separator
	before, after, ok := bytes.Cut(data, []byte{' '})

	if !ok {
		return 0, nil, errors.New("invalid data format: no timestamp found")
	}

	// Parse the timestamp
	issued, err := strconv.ParseInt(string(before), 10, 64)
	if err != nil {
		return 0, nil, fmt.Errorf("parse issued timestamp: %w", err)
	}

	// Return the timestamp and the remaining data (after the space)
	return issued, after, nil
}

// validateIssued the issued timestamp.
func validateIssued(issued int64) error {
	issuedSince := time.Since(time.Unix(issued, 0))

	if issuedSince >= time.Minute*2 {
		return fmt.Errorf("%w: expired after 2 minutes, issued at: %s", ErrInvalid, issuedSince.String())
	}

	if issuedSince <= time.Second*-5 {
		return fmt.Errorf("%w: issued in future, issued at: %s", ErrInvalid, issuedSince.String())
	}

	return nil
}
