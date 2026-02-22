package crypto

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDeriveKey(t *testing.T) {
	tests := []struct {
		name string
		key  string
	}{
		{
			name: "simple key",
			key:  "mykey",
		},
		{
			name: "empty key",
			key:  "",
		},
		{
			name: "long key",
			key:  "this is a very long key that should still produce a 32-byte derived key",
		},
		{
			name: "special characters",
			key:  "key!@#$%^&*()_+-=[]{}|;:,.<>?",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			derivedKey := DeriveKey(tt.key)

			// Check that the result is a 32-byte array
			require.Equal(t, 32, len(derivedKey), "expected key length 32")

			// Check that the same key produces the same result
			derivedKey2 := DeriveKey(tt.key)
			require.True(t, bytes.Equal(derivedKey[:], derivedKey2[:]), "DeriveKey is not deterministic")
		})
	}
}

func TestDeriveKeyDifferentInputs(t *testing.T) {
	key1 := DeriveKey("key1")
	key2 := DeriveKey("key2")

	// Different inputs should produce different keys
	require.False(t, bytes.Equal(key1[:], key2[:]), "different keys should produce different derived keys")
}

func TestNewCipher(t *testing.T) {
	encryptionKey := "test-key"
	cipher := New(encryptionKey)

	require.NotNil(t, cipher, "expected cipher to be non-nil")
	require.Equal(t, encryptionKey, cipher.encryptionKey, "expected encryptionKey to match")
	require.NotNil(t, cipher.derivedKey, "expected derivedKey to be non-nil")
	require.Equal(t, 32, len(cipher.derivedKey), "expected derivedKey length 32")
}

func TestEncryptBytesBasic(t *testing.T) {
	cipher := New("test-key")
	plainText := []byte("hello world")

	encrypted, err := cipher.EncryptBytes(plainText)
	require.NoError(t, err, "EncryptBytes failed")

	// Check that encrypted data is longer than plaintext (nonce + tag overhead)
	require.Greater(t, len(encrypted), len(plainText), "encrypted data should be longer than plaintext")

	// Minimum size: nonce (8) + ciphertext (at least 1) + HMAC tag (16)
	expectedMinSize := salsa20NonceSize + 1 + hmacTagSize
	require.GreaterOrEqual(t, len(encrypted), expectedMinSize, "encrypted data is too short")
}

func TestEncryptBytesEmpty(t *testing.T) {
	cipher := New("test-key")
	plainText := []byte("")

	encrypted, err := cipher.EncryptBytes(plainText)
	require.NoError(t, err, "EncryptBytes failed")

	// Empty plaintext produces: nonce (8 bytes) + empty ciphertext (0 bytes) + HMAC tag (16 bytes) = 24 bytes
	expectedSize := salsa20NonceSize + hmacTagSize
	require.Equal(t, expectedSize, len(encrypted))
}

func TestEncryptBytesRandomNonce(t *testing.T) {
	cipher := New("test-key")
	plainText := []byte("same plaintext")

	encrypted1, err1 := cipher.EncryptBytes(plainText)
	require.NoError(t, err1, "first EncryptBytes failed")

	encrypted2, err2 := cipher.EncryptBytes(plainText)
	require.NoError(t, err2, "second EncryptBytes failed")

	// Same plaintext encrypted twice should produce different ciphertexts (due to random nonce)
	require.NotEqual(t, encrypted1, encrypted2, "same plaintext should produce different ciphertexts due to random nonce")
}

func TestDecryptBytesBasic(t *testing.T) {
	cipher := New("test-key")
	plainText := []byte("hello world")

	encrypted, err := cipher.EncryptBytes(plainText)
	require.NoError(t, err, "EncryptBytes failed")

	decrypted, err := cipher.DecryptBytesBase64(encrypted)
	require.NoError(t, err, "DecryptBytesBase64 failed")
	require.Equal(t, plainText, decrypted, "decrypted text does not match original")
}

func TestDecryptBytesEmpty(t *testing.T) {
	cipher := New("test-key")
	plainText := []byte("")

	encrypted, err := cipher.EncryptBytes(plainText)
	require.NoError(t, err, "EncryptBytes failed")

	// However, decryption of empty plaintext may fail due to minimum size check
	// because we require at least nonce (8) + ciphertext (1) + tag (16) = 25 bytes
	// but empty plaintext only produces nonce (8) + tag (16) = 24 bytes
	_, err = cipher.DecryptBytesBase64(encrypted)
	require.Equal(t, ErrCipherTextBlockSize, err, "expected ErrCipherTextBlockSize for empty plaintext")
}

func TestDecryptBytesTampered(t *testing.T) {
	cipher := New("test-key")
	plainText := []byte("hello world")

	encrypted, err := cipher.EncryptBytes(plainText)
	require.NoError(t, err, "EncryptBytes failed")

	// Tamper with the encrypted data (modify one byte in the middle)
	if len(encrypted) > salsa20NonceSize+1 {
		encrypted[salsa20NonceSize] ^= 0xFF
	}

	_, err = cipher.DecryptBytesBase64(encrypted)
	require.Equal(t, ErrHMACVerificationFailed, err, "expected ErrHMACVerificationFailed for tampered data")
}

func TestDecryptBytesWrongKey(t *testing.T) {
	cipher1 := New("key1")
	cipher2 := New("key2")

	plainText := []byte("secret message")

	encrypted, err := cipher1.EncryptBytes(plainText)
	require.NoError(t, err, "EncryptBytes failed")

	// Try to decrypt with different key
	_, err = cipher2.DecryptBytesBase64(encrypted)
	require.Equal(t, ErrHMACVerificationFailed, err, "expected ErrHMACVerificationFailed when decrypting with wrong key")
}

func TestDecryptBytesShortData(t *testing.T) {
	cipher := New("test-key")

	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte("")},
		{"too short", []byte("short")},
		{"just nonce size", make([]byte, salsa20NonceSize)},
		{"nonce + 1 byte", make([]byte, salsa20NonceSize+1)},
		{"nonce + tag - 1 byte", make([]byte, salsa20NonceSize+hmacTagSize-1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := cipher.DecryptBytesBase64(tt.data)
			require.Equal(t, ErrCipherTextBlockSize, err, "expected ErrCipherTextBlockSize")
		})
	}
}

func TestRoundTrip(t *testing.T) {
	cipher := New("my-secret-key")

	testCases := []struct {
		name      string
		plainText []byte
	}{
		{"single byte", []byte("a")},
		{"small text", []byte("hello")},
		{"longer text", []byte("the quick brown fox jumps over the lazy dog")},
		{"with newlines", []byte("line1\nline2\nline3")},
		{"binary data", []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD}},
		{"large data", bytes.Repeat([]byte("test"), 1000)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			encrypted, err := cipher.EncryptBytes(tc.plainText)
			require.NoError(t, err, "EncryptBytes failed")

			decrypted, err := cipher.DecryptBytesBase64(encrypted)
			require.NoError(t, err, "DecryptBytesBase64 failed")
			require.Equal(t, tc.plainText, decrypted, "round trip failed")
		})
	}
}

func TestCipherConsistency(t *testing.T) {
	// Two ciphers with the same key should decrypt each other's output
	key := "consistent-key"
	cipher1 := New(key)
	cipher2 := New(key)

	plainText := []byte("consistency test")

	encrypted1, err := cipher1.EncryptBytes(plainText)
	require.NoError(t, err, "cipher1 EncryptBytes failed")

	decrypted2, err := cipher2.DecryptBytesBase64(encrypted1)
	require.NoError(t, err, "cipher2 DecryptBytesBase64 failed")
	require.Equal(t, plainText, decrypted2, "ciphers with same key should be compatible")
}

func TestMultipleEncryptionRounds(t *testing.T) {
	cipher := New("test-key")
	plainTexts := [][]byte{
		[]byte("first message"),
		[]byte("second message"),
		[]byte("third message"),
	}

	for i, plainText := range plainTexts {
		encrypted, err := cipher.EncryptBytes(plainText)
		require.NoError(t, err, "round %d EncryptBytes failed", i+1)

		decrypted, err := cipher.DecryptBytesBase64(encrypted)
		require.NoError(t, err, "round %d DecryptBytesBase64 failed", i+1)
		require.Equal(t, plainText, decrypted, "round %d failed", i+1)
	}
}

func BenchmarkDeriveKey(b *testing.B) {
	key := "benchmark-key"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DeriveKey(key)
	}
}

func BenchmarkNewCipher(b *testing.B) {
	key := "benchmark-key"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		New(key)
	}
}

func BenchmarkEncryptBytes(b *testing.B) {
	cipher := New("benchmark-key")
	plainText := []byte("benchmark plaintext")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = cipher.EncryptBytes(plainText)
	}
}

func BenchmarkDecryptBytes(b *testing.B) {
	cipher := New("benchmark-key")
	plainText := []byte("benchmark plaintext")
	encrypted, _ := cipher.EncryptBytes(plainText)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = cipher.DecryptBytesBase64(encrypted)
	}
}

func BenchmarkRoundTrip(b *testing.B) {
	cipher := New("benchmark-key")
	plainText := []byte("benchmark plaintext")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypted, _ := cipher.EncryptBytes(plainText)
		_, _ = cipher.DecryptBytesBase64(encrypted)
	}
}
