package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	aes256KeySize     = 32
	aesGCMNonceSize   = 12
	aesGCMTagSize     = 16
	keyDerivationInfo = "aes-256-gcm"
	defaultMaxAge     = 2 * time.Minute

	// timedPlainTextScratchSize covers typical authentication payloads while append retains a heap fallback.
	timedPlainTextScratchSize = 128
	timedEncryptedScratchSize = timedPlainTextScratchSize + aesGCMNonceSize + aesGCMTagSize
	base64SourceChunkSize     = timedEncryptedScratchSize - timedEncryptedScratchSize%3
	base64EncodedChunkSize    = base64SourceChunkSize / 3 * 4
)

// ErrCipherTextBlockSize is returned when the ciphertext block size is too short.
var ErrCipherTextBlockSize = errors.New("ciphertext block size is too short")

// ErrAuthenticationFailed is returned when ciphertext authentication fails.
var ErrAuthenticationFailed = errors.New("ciphertext authentication failed")

// Cipher provides authenticated encryption using AES-256-GCM.
type Cipher struct {
	scratchPool sync.Pool
	aead        cipher.AEAD
	maxAge      time.Duration
}

// pooledScratch keeps timed-encryption and decryption scratch between calls.
type pooledScratch struct {
	encrypted [timedEncryptedScratchSize]byte
}

// New creates a new Cipher instance with the given encryption key.
// The AEAD key is derived from the input with HKDF-SHA256. The raw key string is
// not retained in the Cipher after construction.
func New(encryptionKey string) *Cipher {
	return NewWithMaxAge(encryptionKey, defaultMaxAge)
}

// NewWithMaxAge creates a new Cipher instance with the given encryption key and
// maximum age for timestamped payloads.
func NewWithMaxAge(encryptionKey string, maxAge time.Duration) *Cipher {
	key := DeriveKey(encryptionKey)
	defer clear(key[:])

	block, err := aes.NewCipher(key[:])
	if err != nil {
		panic(fmt.Sprintf("aes.NewCipher: unexpected error: %v", err))
	}

	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		panic(fmt.Sprintf("cipher.NewGCMWithRandomNonce: unexpected error: %v", err))
	}

	result := &Cipher{
		aead:   aead,
		maxAge: maxAge,
	}
	result.scratchPool.New = func() any {
		return new(pooledScratch)
	}

	return result
}

// DeriveKey derives a 32-byte AES-256 key using HKDF-SHA256.
func DeriveKey(key string) *[32]byte {
	derivedKey, err := hkdf.Key(sha256.New, []byte(key), nil, keyDerivationInfo, aes256KeySize)
	if err != nil {
		// hkdf.Key only errors when keyLength exceeds 255 times the hash size.
		panic(fmt.Sprintf("hkdf.Key: unexpected error: %v", err))
	}
	defer clear(derivedKey)

	var result [32]byte
	copy(result[:], derivedKey)

	return &result
}

// EncryptBytes encrypts and authenticates data using AES-256-GCM.
func (c *Cipher) EncryptBytes(plainText []byte) ([]byte, error) {
	return c.encryptBytesInto(nil, plainText)
}

// DecryptBytes decrypts data encrypted with EncryptBytes.
func (c *Cipher) DecryptBytes(encryptedData []byte) ([]byte, error) {
	if len(encryptedData) < c.aead.Overhead() {
		return nil, ErrCipherTextBlockSize
	}

	return c.decryptBytesInto(nil, encryptedData)
}

// EncryptBytesWithTime prefixes plaintext with the current Unix timestamp,
// encrypts it, and returns raw URL-base64 bytes.
func (c *Cipher) EncryptBytesWithTime(plainText []byte) ([]byte, error) {
	scratch := c.getScratch()
	defer c.putScratch(scratch)

	encrypted, err := c.encryptTimedBytes(scratch.encrypted[:0], plainText)
	if err != nil {
		return nil, err
	}

	encryptedBase64 := make([]byte, base64.RawURLEncoding.EncodedLen(len(encrypted)))

	base64.RawURLEncoding.Encode(encryptedBase64, encrypted)

	return encryptedBase64, nil
}

// EncryptStringWithTime prefixes plaintext with the current Unix timestamp,
// encrypts it, and returns a raw URL-base64 string.
func (c *Cipher) EncryptStringWithTime(plainText []byte) (string, error) {
	scratch := c.getScratch()
	defer c.putScratch(scratch)

	encrypted, err := c.encryptTimedBytes(scratch.encrypted[:0], plainText)
	if err != nil {
		return "", err
	}

	return encodeRawURLBase64String(encrypted), nil
}

// DecryptBytesWithTime decodes, authenticates, decrypts, and validates the timestamp on raw URL-base64 input.
func (c *Cipher) DecryptBytesWithTime(encryptedBase64 []byte) ([]byte, error) {
	if err := checkTokenSize(len(encryptedBase64)); err != nil {
		return nil, err
	}

	encrypted := make([]byte, base64.RawURLEncoding.DecodedLen(len(encryptedBase64)))

	decodedLen, err := base64.RawURLEncoding.Decode(encrypted, encryptedBase64)
	if err != nil {
		return nil, fmt.Errorf("base64 decode %q: %w", encryptedBase64, err)
	}

	return c.decryptTimedPayload(encrypted[:decodedLen])
}

// DecryptStringWithTime decodes, authenticates, decrypts, and validates
// the timestamp on raw URL-base64 string input.
func (c *Cipher) DecryptStringWithTime(encryptedBase64 string) ([]byte, error) {
	if err := checkTokenSize(len(encryptedBase64)); err != nil {
		return nil, err
	}

	encrypted, err := base64.RawURLEncoding.DecodeString(encryptedBase64)
	if err != nil {
		return nil, fmt.Errorf("base64 decode %q: %w", encryptedBase64, err)
	}

	return c.decryptTimedPayload(encrypted)
}

// DecryptStringWithTimeInto decodes, authenticates, decrypts, and validates
// raw URL-base64 input into dst. On success, it returns the plaintext length.
// If dst is too short, it returns the required decoded capacity with io.ErrShortBuffer.
func (c *Cipher) DecryptStringWithTimeInto(dst []byte, encryptedBase64 string) (int, error) {
	if err := checkTokenSize(len(encryptedBase64)); err != nil {
		return 0, err
	}

	decodedLen := base64.RawURLEncoding.DecodedLen(len(encryptedBase64))
	if len(dst) < decodedLen {
		return decodedLen, io.ErrShortBuffer
	}

	scratch := c.getScratch()
	defer c.putScratch(scratch)

	var encrypted []byte
	if decodedLen > cap(scratch.encrypted) {
		encrypted = make([]byte, decodedLen)
	} else {
		encrypted = scratch.encrypted[:decodedLen]
	}

	decodedLen, err := base64.RawURLEncoding.Decode(encrypted, []byte(encryptedBase64))
	if err != nil {
		return 0, fmt.Errorf("base64 decode %q: %w", encryptedBase64, err)
	}

	plainText, err := c.decryptTimedPayload(encrypted[:decodedLen])
	if err != nil {
		return 0, err
	}

	return copy(dst, plainText), nil
}

// encryptTimedBytes prefixes plaintext with a timestamp and encrypts it into dst.
func (c *Cipher) encryptTimedBytes(dst, plainText []byte) ([]byte, error) {
	issued := time.Now().Round(time.Second).Unix()

	var scratch [timedPlainTextScratchSize]byte

	timedPlainText := strconv.AppendInt(scratch[:0], issued, 10)
	timedPlainText = append(timedPlainText, ' ')
	timedPlainText = append(timedPlainText, plainText...)

	return c.encryptBytesInto(dst, timedPlainText)
}

func encodeRawURLBase64String(src []byte) string {
	var encoded strings.Builder
	encoded.Grow(base64.RawURLEncoding.EncodedLen(len(src)))

	var scratch [base64EncodedChunkSize]byte

	for len(src) > base64SourceChunkSize {
		base64.RawURLEncoding.Encode(scratch[:], src[:base64SourceChunkSize])
		_, _ = encoded.Write(scratch[:])

		src = src[base64SourceChunkSize:]
	}

	encodedLen := base64.RawURLEncoding.EncodedLen(len(src))
	base64.RawURLEncoding.Encode(scratch[:encodedLen], src)
	_, _ = encoded.Write(scratch[:encodedLen])

	return encoded.String()
}

// encryptBytesInto encrypts plainText into dst, allocating only when its capacity is insufficient.
func (c *Cipher) encryptBytesInto(dst, plainText []byte) ([]byte, error) {
	resultSize := len(plainText) + c.aead.Overhead()

	if cap(dst) < resultSize {
		dst = make([]byte, 0, resultSize)
	} else {
		dst = dst[:0]
	}

	return c.aead.Seal(dst, nil, plainText, nil), nil
}

// decryptBytesInto authenticates encryptedData and decrypts it into dst.
// Callers must reject ciphertext shorter than the nonce and authentication tag.
func (c *Cipher) decryptBytesInto(dst, encryptedData []byte) ([]byte, error) {
	plainText, err := c.aead.Open(dst, nil, encryptedData, nil)
	if err != nil {
		return nil, ErrAuthenticationFailed
	}

	return plainText, nil
}

// decryptTimedPayload authenticates, decrypts, and validates
// an already base64-decoded timestamped payload.
func (c *Cipher) decryptTimedPayload(encrypted []byte) ([]byte, error) {
	if len(encrypted) < c.aead.Overhead() {
		return nil, ErrCipherTextBlockSize
	}

	data, err := c.decryptBytesInto(
		encrypted[:0],
		encrypted,
	)
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

// getScratch returns reusable scratch for timed encryption and decryption.
func (c *Cipher) getScratch() *pooledScratch {
	scratch, ok := c.scratchPool.Get().(*pooledScratch)
	if !ok {
		return new(pooledScratch)
	}

	return scratch
}

// putScratch clears plaintext before returning scratch to the pool.
func (c *Cipher) putScratch(scratch *pooledScratch) {
	clear(scratch.encrypted[:])
	c.scratchPool.Put(scratch)
}

// checkTokenSize rejects unreasonably large encoded payloads before allocating decode buffers.
func checkTokenSize(encodedLength int) error {
	if encodedLength > 4096 {
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
