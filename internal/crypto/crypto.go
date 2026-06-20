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
	"hash"
	"io"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/salsa20"
)

const (
	salsa20NonceSize = 8
	hmacTagSize      = 16
	derivedKeySize   = 32
	defaultMaxAge    = 2 * time.Minute
)

// ErrCipherTextBlockSize is returned when the ciphertext block size is too short.
var ErrCipherTextBlockSize = errors.New("ciphertext block size is too short")

// ErrHMACVerificationFailed is returned when HMAC verification fails.
var ErrHMACVerificationFailed = errors.New("hmac verification failed")

// Cipher provides encryption and decryption operations using Salsa20 + HMAC-SHA256.
type Cipher struct {
	macPool sync.Pool
	encKey  *[32]byte
	macKey  []byte
	maxAge  time.Duration
}

// New creates a new Cipher instance with the given encryption key.
// Both the encryption key and the MAC key are independently derived from the
// input using HKDF-SHA256 with distinct info strings ("salsa20-encryption" and
// "hmac-authentication") to ensure domain separation. The raw key string is not
// retained in memory after construction.
func New(encryptionKey string) *Cipher {
	return NewWithMaxAge(encryptionKey, defaultMaxAge)
}

// NewWithMaxAge creates a new Cipher instance with the given encryption key and
// maximum age for timestamped payloads.
func NewWithMaxAge(encryptionKey string, maxAge time.Duration) *Cipher {
	secret := []byte(encryptionKey)

	encKeyBytes := deriveHKDFKey(secret, "salsa20-encryption")
	macKeyBytes := deriveHKDFKey(secret, "hmac-authentication")

	var encKey [32]byte
	copy(encKey[:], encKeyBytes)

	cipher := &Cipher{
		encKey: &encKey,
		macKey: macKeyBytes,
		maxAge: maxAge,
	}
	cipher.macPool.New = func() any {
		return hmac.New(sha256.New, cipher.macKey)
	}

	return cipher
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
	result := make([]byte, salsa20NonceSize+len(plainText)+hmacTagSize)
	nonce := result[:salsa20NonceSize]

	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	cipherText := result[salsa20NonceSize : len(result)-hmacTagSize]
	salsa20.XORKeyStream(cipherText, plainText, nonce, c.encKey)

	macHash := c.getMAC()
	defer c.putMAC(macHash)

	macHash.Write(nonce)
	macHash.Write(cipherText)

	var tagScratch [sha256.Size]byte

	tag := macHash.Sum(tagScratch[:0])
	copy(result[len(result)-hmacTagSize:], tag[:hmacTagSize])

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
	macHash := c.getMAC()
	defer c.putMAC(macHash)

	macHash.Write(nonce)
	macHash.Write(cipherText)

	var tagScratch [sha256.Size]byte

	expectedTag := macHash.Sum(tagScratch[:0])

	if !hmac.Equal(tag, expectedTag[:hmacTagSize]) {
		return nil, ErrHMACVerificationFailed
	}

	// Decrypt using Salsa20
	plainText := make([]byte, len(cipherText))
	salsa20.XORKeyStream(plainText, cipherText, nonce, c.encKey)

	return plainText, nil
}

// EncryptBytesWithTime prefixes plaintext with the current Unix timestamp, encrypts it, and returns raw URL-base64 bytes.
func (c *Cipher) EncryptBytesWithTime(plainText []byte) ([]byte, error) {
	issued := time.Now().Round(time.Second).Unix()
	timedPlainText := strconv.AppendInt(make([]byte, 0, len(plainText)+12), issued, 10)
	timedPlainText = append(timedPlainText, ' ')
	timedPlainText = append(timedPlainText, plainText...)

	encrypted, err := c.EncryptBytes(timedPlainText)
	if err != nil {
		return nil, err
	}

	encryptedBase64 := make([]byte, base64.RawURLEncoding.EncodedLen(len(encrypted)))

	base64.RawURLEncoding.Encode(encryptedBase64, encrypted)

	return encryptedBase64, nil
}

// DecryptBytesWithTime decodes, authenticates, decrypts, and validates the timestamp on raw URL-base64 input.
func (c *Cipher) DecryptBytesWithTime(encryptedBase64 []byte) ([]byte, error) {
	if err := checkTokenSize(encryptedBase64); err != nil {
		return nil, err
	}

	encrypted := make([]byte, base64.RawURLEncoding.DecodedLen(len(encryptedBase64)))

	decodedLen, err := base64.RawURLEncoding.Decode(encrypted, encryptedBase64)
	if err != nil {
		return nil, fmt.Errorf("base64 decode %q: %w", encryptedBase64, err)
	}

	data, err := c.DecryptBytes(encrypted[:decodedLen])
	if err != nil {
		return nil, err
	}

	issued, data, err := extractIssued(data)
	if err != nil {
		return nil, err
	}

	if err := c.validateIssued(issued); err != nil {
		return nil, err
	}

	return data, nil
}

// getMAC returns a reset HMAC-SHA256 instance from the cipher-local pool.
func (c *Cipher) getMAC() hash.Hash {
	macHash, ok := c.macPool.Get().(hash.Hash)
	if !ok {
		return hmac.New(sha256.New, c.macKey)
	}

	return macHash
}

// putMAC resets and returns an HMAC-SHA256 instance to the cipher-local pool.
func (c *Cipher) putMAC(macHash hash.Hash) {
	macHash.Reset()
	c.macPool.Put(macHash)
}

// checkTokenSize rejects unreasonably large encoded payloads before allocating decode buffers.
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

// validateIssued checks that the issued timestamp is within the accepted clock window.
func (c *Cipher) validateIssued(issued int64) error {
	issuedSince := time.Since(time.Unix(issued, 0))

	if issuedSince >= c.maxAge {
		return fmt.Errorf("%w: expired after %s, issued at: %s", ErrInvalid, c.maxAge, issuedSince.String())
	}

	if issuedSince <= time.Second*-5 {
		return fmt.Errorf("%w: issued in future, issued at: %s", ErrInvalid, issuedSince.String())
	}

	return nil
}
