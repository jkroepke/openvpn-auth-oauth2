package crypto_test

import (
	"bytes"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/crypto"
	"github.com/stretchr/testify/require"
)

func TestDeriveKey(t *testing.T) {
	t.Parallel()

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

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			derivedKey := crypto.DeriveKey(tc.key)

			// Check that the result is a 32-byte array
			require.Len(t, derivedKey, 32, "expected key length 32")

			// Check that the same key produces the same result
			derivedKey2 := crypto.DeriveKey(tc.key)
			require.True(t, bytes.Equal(derivedKey[:], derivedKey2[:]), "DeriveKey is not deterministic")
		})
	}
}

func TestDeriveKeyDifferentInputs(t *testing.T) {
	t.Parallel()

	key1 := crypto.DeriveKey("key1")
	key2 := crypto.DeriveKey("key2")

	// Different inputs should produce different keys
	require.False(t, bytes.Equal(key1[:], key2[:]), "different keys should produce different derived keys")
}

func TestNewCipher(t *testing.T) {
	t.Parallel()

	encryptionKey := "test-key"
	cipher := crypto.New(encryptionKey)

	require.NotNil(t, cipher, "expected cipher to be non-nil")

	plainText := []byte("ping")
	encrypted, err := cipher.EncryptBytes(plainText)
	require.NoError(t, err, "EncryptBytes failed")

	decrypted, err := cipher.DecryptBytesBase64(encrypted)
	require.NoError(t, err, "DecryptBytesBase64 failed")
	require.Equal(t, plainText, decrypted, "round trip failed")
}

func TestEncryptBytesBasic(t *testing.T) {
	t.Parallel()

	cipher := crypto.New("test-key")
	plainText := []byte("hello world")

	encrypted, err := cipher.EncryptBytes(plainText)
	require.NoError(t, err, "EncryptBytes failed")

	// Check that encrypted data is longer than plaintext (nonce + tag overhead)
	require.Greater(t, len(encrypted), len(plainText), "encrypted data should be longer than plaintext")

	// Minimum size: nonce (8) + ciphertext (at least 1) + HMAC tag (16)
	expectedMinSize := 8 + 1 + 16
	require.GreaterOrEqual(t, len(encrypted), expectedMinSize, "encrypted data is too short")
}

func TestEncryptBytesEmpty(t *testing.T) {
	t.Parallel()

	cipher := crypto.New("test-key")
	plainText := []byte("")

	encrypted, err := cipher.EncryptBytes(plainText)
	require.NoError(t, err, "EncryptBytes failed")

	// Empty plaintext produces: nonce (8 bytes) + empty ciphertext (0 bytes) + HMAC tag (16 bytes) = 24 bytes
	expectedSize := 8 + 16
	require.Len(t, encrypted, expectedSize)
}

func TestEncryptBytesRandomNonce(t *testing.T) {
	t.Parallel()

	cipher := crypto.New("test-key")
	plainText := []byte("same plaintext")

	encrypted1, err1 := cipher.EncryptBytes(plainText)
	require.NoError(t, err1, "first EncryptBytes failed")

	encrypted2, err2 := cipher.EncryptBytes(plainText)
	require.NoError(t, err2, "second EncryptBytes failed")

	// Same plaintext encrypted twice should produce different ciphertexts (due to random nonce)
	require.NotEqual(t, encrypted1, encrypted2, "same plaintext should produce different ciphertexts due to random nonce")
}

func TestDecryptBytesBasic(t *testing.T) {
	t.Parallel()

	cipher := crypto.New("test-key")
	plainText := []byte("hello world")

	encrypted, err := cipher.EncryptBytes(plainText)
	require.NoError(t, err, "EncryptBytes failed")

	decrypted, err := cipher.DecryptBytesBase64(encrypted)
	require.NoError(t, err, "DecryptBytesBase64 failed")
	require.Equal(t, plainText, decrypted, "decrypted text does not match original")
}

func TestDecryptBytesEmpty(t *testing.T) {
	t.Parallel()

	cipher := crypto.New("test-key")
	plainText := []byte("")

	encrypted, err := cipher.EncryptBytes(plainText)
	require.NoError(t, err, "EncryptBytes failed")

	// However, decryption of empty plaintext may fail due to minimum size check
	// because we require at least nonce (8) + ciphertext (1) + tag (16) = 25 bytes
	// but empty plaintext only produces nonce (8) + tag (16) = 24 bytes
	_, err = cipher.DecryptBytesBase64(encrypted)
	require.Equal(t, crypto.ErrCipherTextBlockSize, err, "expected ErrCipherTextBlockSize for empty plaintext")
}

func TestDecryptBytesTampered(t *testing.T) {
	t.Parallel()

	cipher := crypto.New("test-key")
	plainText := []byte("hello world")

	encrypted, err := cipher.EncryptBytes(plainText)
	require.NoError(t, err, "EncryptBytes failed")

	// Tamper with the encrypted data (modify one byte in the middle)
	if len(encrypted) > 8+1 {
		encrypted[8] ^= 0xFF
	}

	_, err = cipher.DecryptBytesBase64(encrypted)
	require.Equal(t, crypto.ErrHMACVerificationFailed, err, "expected ErrHMACVerificationFailed for tampered data")
}

func TestDecryptBytesWrongKey(t *testing.T) {
	t.Parallel()

	cipher1 := crypto.New("key1")
	cipher2 := crypto.New("key2")

	plainText := []byte("secret message")

	encrypted, err := cipher1.EncryptBytes(plainText)
	require.NoError(t, err, "EncryptBytes failed")

	// Try to decrypt with different key
	_, err = cipher2.DecryptBytesBase64(encrypted)
	require.Equal(t, crypto.ErrHMACVerificationFailed, err, "expected ErrHMACVerificationFailed when decrypting with wrong key")
}

func TestDecryptBytesShortData(t *testing.T) {
	t.Parallel()

	cipher := crypto.New("test-key")

	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte("")},
		{"too short", []byte("short")},
		{"just nonce size", make([]byte, 8)},
		{"nonce + 1 byte", make([]byte, 8+1)},
		{"nonce + tag - 1 byte", make([]byte, 8+16-1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := cipher.DecryptBytesBase64(tt.data)
			require.Equal(t, crypto.ErrCipherTextBlockSize, err, "expected ErrCipherTextBlockSize")
		})
	}
}

func TestRoundTrip(t *testing.T) {
	t.Parallel()

	cipher := crypto.New("my-secret-key")

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
			t.Parallel()

			encrypted, err := cipher.EncryptBytes(tc.plainText)
			require.NoError(t, err, "EncryptBytes failed")

			decrypted, err := cipher.DecryptBytesBase64(encrypted)
			require.NoError(t, err, "DecryptBytesBase64 failed")
			require.Equal(t, tc.plainText, decrypted, "round trip failed")
		})
	}
}

func TestCipherConsistency(t *testing.T) {
	t.Parallel()

	// Two ciphers with the same key should decrypt each other's output
	key := "consistent-key"
	cipher1 := crypto.New(key)
	cipher2 := crypto.New(key)

	plainText := []byte("consistency test")

	encrypted1, err := cipher1.EncryptBytes(plainText)
	require.NoError(t, err, "cipher1 EncryptBytes failed")

	decrypted2, err := cipher2.DecryptBytesBase64(encrypted1)
	require.NoError(t, err, "cipher2 DecryptBytesBase64 failed")
	require.Equal(t, plainText, decrypted2, "ciphers with same key should be compatible")
}

func TestMultipleEncryptionRounds(t *testing.T) {
	t.Parallel()

	cipher := crypto.New("test-key")
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

	for b.Loop() {
		crypto.DeriveKey(key)
	}
}

func BenchmarkNewCipher(b *testing.B) {
	key := "benchmark-key"

	b.ResetTimer()

	for b.Loop() {
		crypto.New(key)
	}
}

func BenchmarkEncryptBytes(b *testing.B) {
	cipher := crypto.New("benchmark-key")
	plainText := []byte("benchmark plaintext")

	b.ResetTimer()

	for b.Loop() {
		_, _ = cipher.EncryptBytes(plainText)
	}
}

func BenchmarkDecryptBytes(b *testing.B) {
	cipher := crypto.New("benchmark-key")
	plainText := []byte("benchmark plaintext")
	encrypted, _ := cipher.EncryptBytes(plainText)

	b.ResetTimer()

	for b.Loop() {
		_, _ = cipher.DecryptBytesBase64(encrypted)
	}
}

func BenchmarkRoundTrip(b *testing.B) {
	cipher := crypto.New("benchmark-key")
	plainText := []byte("benchmark plaintext")

	b.ResetTimer()

	for b.Loop() {
		encrypted, _ := cipher.EncryptBytes(plainText)
		_, _ = cipher.DecryptBytesBase64(encrypted)
	}
}
