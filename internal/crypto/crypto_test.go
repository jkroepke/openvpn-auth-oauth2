package crypto_test

import (
	"bytes"
	"crypto/aes"
	stdcipher "crypto/cipher"
	"encoding/base64"
	"io"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/crypto"
	"github.com/stretchr/testify/require"
)

const (
	aesGCMNonceSize = 12
	aesGCMTagSize   = 16
	aesGCMOverhead  = aesGCMNonceSize + aesGCMTagSize
)

func newCipher(tb testing.TB, key string) *crypto.Cipher {
	tb.Helper()

	cipher, err := crypto.New(key)
	require.NoError(tb, err)

	return cipher
}

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

			derivedKey, err := crypto.DeriveKey(tc.key)
			require.NoError(t, err)

			// Check that the result is a 32-byte array
			require.Len(t, derivedKey[:], 32, "expected key length 32")

			// Check that the same key produces the same result
			derivedKey2, err := crypto.DeriveKey(tc.key)
			require.NoError(t, err)
			require.True(t, bytes.Equal(derivedKey[:], derivedKey2[:]), "DeriveKey is not deterministic")
		})
	}
}

func TestDeriveKeyDifferentInputs(t *testing.T) {
	t.Parallel()

	key1, err := crypto.DeriveKey("key1")
	require.NoError(t, err)
	key2, err := crypto.DeriveKey("key2")
	require.NoError(t, err)

	// Different inputs should produce different keys
	require.False(t, bytes.Equal(key1[:], key2[:]), "different keys should produce different derived keys")
}

func TestNewCipher(t *testing.T) {
	t.Parallel()

	encryptionKey := "test-key"
	cipher, err := crypto.New(encryptionKey)
	require.NoError(t, err)

	require.NotNil(t, cipher, "expected cipher to be non-nil")

	plainText := []byte("ping")
	encrypted, err := cipher.EncryptBytes(plainText)
	require.NoError(t, err, "EncryptBytes failed")

	decrypted, err := cipher.DecryptBytes(encrypted)
	require.NoError(t, err, "DecryptBytes failed")
	require.Equal(t, plainText, decrypted, "round trip failed")
}

func TestEncryptBytesBasic(t *testing.T) {
	t.Parallel()

	cipher := newCipher(t, "test-key")
	plainText := []byte("hello world")

	encrypted, err := cipher.EncryptBytes(plainText)
	require.NoError(t, err, "EncryptBytes failed")

	expectedSize := len(plainText) + aesGCMOverhead
	require.Len(t, encrypted, expectedSize)

	key, err := crypto.DeriveKey("test-key")
	require.NoError(t, err)
	block, err := aes.NewCipher(key[:])
	require.NoError(t, err)
	aead, err := stdcipher.NewGCMWithRandomNonce(block)
	require.NoError(t, err)

	decrypted, err := aead.Open(nil, nil, encrypted, nil)
	require.NoError(t, err)
	require.Equal(t, plainText, decrypted)
}

func TestEncryptBytesEmpty(t *testing.T) {
	t.Parallel()

	cipher := newCipher(t, "test-key")
	plainText := []byte("")

	encrypted, err := cipher.EncryptBytes(plainText)
	require.NoError(t, err, "EncryptBytes failed")

	require.Len(t, encrypted, aesGCMOverhead)
}

func TestEncryptBytesRandomNonce(t *testing.T) {
	t.Parallel()

	cipher := newCipher(t, "test-key")
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

	cipher := newCipher(t, "test-key")
	plainText := []byte("hello world")

	encrypted, err := cipher.EncryptBytes(plainText)
	require.NoError(t, err, "EncryptBytes failed")

	encryptedCopy := bytes.Clone(encrypted)

	decrypted, err := cipher.DecryptBytes(encrypted)
	require.NoError(t, err, "DecryptBytes failed")
	require.Equal(t, plainText, decrypted, "decrypted text does not match original")
	require.Equal(t, encryptedCopy, encrypted, "DecryptBytes must not modify ciphertext")
}

func TestDecryptBytesTampered(t *testing.T) {
	t.Parallel()

	cipher := newCipher(t, "test-key")
	plainText := []byte("hello world")

	encrypted, err := cipher.EncryptBytes(plainText)
	require.NoError(t, err, "EncryptBytes failed")

	encrypted[len(encrypted)/2] ^= 0xFF

	_, err = cipher.DecryptBytes(encrypted)
	require.ErrorIs(t, err, crypto.ErrAuthenticationFailed)
}

func TestDecryptBytesWrongKey(t *testing.T) {
	t.Parallel()

	cipher1 := newCipher(t, "key1")
	cipher2 := newCipher(t, "key2")

	plainText := []byte("secret message")

	encrypted, err := cipher1.EncryptBytes(plainText)
	require.NoError(t, err, "EncryptBytes failed")

	// Try to decrypt with different key
	_, err = cipher2.DecryptBytes(encrypted)
	require.ErrorIs(t, err, crypto.ErrAuthenticationFailed)
}

func TestDecryptBytesShortData(t *testing.T) {
	t.Parallel()

	cipher := newCipher(t, "test-key")

	tests := []struct {
		name string
		data []byte
	}{
		{name: "empty", data: []byte("")},
		{name: "too short", data: []byte("short")},
		{name: "just nonce size", data: make([]byte, aesGCMNonceSize)},
		{name: "nonce + 1 byte", data: make([]byte, aesGCMNonceSize+1)},
		{
			name: "nonce + tag - 1 byte",
			data: make([]byte, aesGCMOverhead-1),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := cipher.DecryptBytes(tt.data)
			require.ErrorIs(t, err, crypto.ErrCipherTextBlockSize)
		})
	}
}

func TestRoundTrip(t *testing.T) {
	t.Parallel()

	cipher := newCipher(t, "my-secret-key")

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

			decrypted, err := cipher.DecryptBytes(encrypted)
			require.NoError(t, err, "DecryptBytes failed")
			require.Equal(t, tc.plainText, decrypted, "round trip failed")
		})
	}
}

func TestEncryptBytesWithTimeUsesRawURLBase64(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name      string
		plainText []byte
	}{
		{name: "small payload", plainText: []byte("hello world")},
		{name: "large payload", plainText: bytes.Repeat([]byte("a"), 512)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cipher := newCipher(t, "test-key")

			encrypted, err := cipher.EncryptBytesWithTime(tc.plainText)
			require.NoError(t, err)

			require.NotContains(t, string(encrypted), "=")

			decrypted, err := cipher.DecryptBytesWithTime(encrypted)
			require.NoError(t, err)
			require.Equal(t, tc.plainText, decrypted)
		})
	}
}

func TestEncryptStringWithTimeUsesRawURLBase64(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name      string
		plainText []byte
	}{
		{name: "small payload", plainText: []byte("hello world")},
		{name: "large payload", plainText: bytes.Repeat([]byte("a"), 512)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cipher := newCipher(t, "test-key")

			encrypted, err := cipher.EncryptStringWithTime(tc.plainText)
			require.NoError(t, err)

			require.NotContains(t, encrypted, "=")

			decrypted, err := cipher.DecryptStringWithTime(encrypted)
			require.NoError(t, err)
			require.Equal(t, tc.plainText, decrypted)
		})
	}
}

func TestDecryptBytesWithTimeMaxAge(t *testing.T) {
	t.Parallel()

	const key = "test-key"

	issued := time.Now().Add(-3 * time.Minute).Unix()
	plainText := strconv.AppendInt(nil, issued, 10)
	plainText = append(plainText, " payload"...)
	cipher := newCipher(t, key)
	encrypted, err := cipher.EncryptBytes(plainText)
	require.NoError(t, err)

	encoded := make([]byte, base64.RawURLEncoding.EncodedLen(len(encrypted)))
	base64.RawURLEncoding.Encode(encoded, encrypted)

	_, err = cipher.DecryptBytesWithTime(encoded)
	require.ErrorContains(t, err, "expired after 2m0s")

	longLivedCipher, err := crypto.NewWithMaxAge(key, 4*time.Minute)
	require.NoError(t, err)
	decrypted, err := longLivedCipher.DecryptBytesWithTime(encoded)
	require.NoError(t, err)
	require.Equal(t, []byte("payload"), decrypted)
}

func TestDecryptStringWithTime(t *testing.T) {
	t.Parallel()

	cipher := newCipher(t, "test-key")

	encrypted, err := cipher.EncryptBytesWithTime([]byte("hello world"))
	require.NoError(t, err)

	decrypted, err := cipher.DecryptStringWithTime(string(encrypted))
	require.NoError(t, err)
	require.Equal(t, []byte("hello world"), decrypted)
}

func TestDecryptStringWithTimeInto(t *testing.T) {
	t.Parallel()

	cipher := newCipher(t, "test-key")

	encrypted, err := cipher.EncryptStringWithTime([]byte("hello world"))
	require.NoError(t, err)

	var scratch [128]byte

	decryptedLen, err := cipher.DecryptStringWithTimeInto(scratch[:], encrypted)
	require.NoError(t, err)
	require.Equal(t, []byte("hello world"), scratch[:decryptedLen])

	requiredLen, err := cipher.DecryptStringWithTimeInto(scratch[:1], encrypted)
	require.ErrorIs(t, err, io.ErrShortBuffer)
	require.Equal(t, base64.RawURLEncoding.DecodedLen(len(encrypted)), requiredLen)
}

func TestCipherConsistency(t *testing.T) {
	t.Parallel()

	// Two ciphers with the same key should decrypt each other's output
	key := "consistent-key"
	cipher1 := newCipher(t, key)
	cipher2 := newCipher(t, key)

	plainText := []byte("consistency test")

	encrypted1, err := cipher1.EncryptBytes(plainText)
	require.NoError(t, err, "cipher1 EncryptBytes failed")

	decrypted2, err := cipher2.DecryptBytes(encrypted1)
	require.NoError(t, err, "cipher2 DecryptBytes failed")
	require.Equal(t, plainText, decrypted2, "ciphers with same key should be compatible")
}

func TestMultipleEncryptionRounds(t *testing.T) {
	t.Parallel()

	cipher := newCipher(t, "test-key")
	plainTexts := [][]byte{
		[]byte("first message"),
		[]byte("second message"),
		[]byte("third message"),
	}

	for i, plainText := range plainTexts {
		encrypted, err := cipher.EncryptBytes(plainText)
		require.NoError(t, err, "round %d EncryptBytes failed", i+1)

		decrypted, err := cipher.DecryptBytes(encrypted)
		require.NoError(t, err, "round %d DecryptBytes failed", i+1)
		require.Equal(t, plainText, decrypted, "round %d failed", i+1)
	}
}

func TestCipherConcurrentUse(t *testing.T) {
	t.Parallel()

	const workerCount = 16

	cipher := newCipher(t, "test-key")
	plainText := []byte("concurrent message")

	var wg sync.WaitGroup

	for range workerCount {
		wg.Go(func() {
			for range 100 {
				encrypted, err := cipher.EncryptBytes(plainText)
				if err != nil {
					t.Errorf("EncryptBytes failed: %v", err)

					return
				}

				decrypted, err := cipher.DecryptBytes(encrypted)
				if err != nil {
					t.Errorf("DecryptBytes failed: %v", err)

					return
				}

				if !bytes.Equal(plainText, decrypted) {
					t.Errorf("decrypted text %q does not match %q", decrypted, plainText)

					return
				}
			}
		})
	}

	wg.Wait()
}

func BenchmarkDeriveKey(b *testing.B) {
	key := "benchmark-key"

	b.ResetTimer()

	for b.Loop() {
		if _, err := crypto.DeriveKey(key); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNewCipher(b *testing.B) {
	key := "benchmark-key"

	b.ResetTimer()

	for b.Loop() {
		if _, err := crypto.New(key); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncryptBytes(b *testing.B) {
	cipher := newCipher(b, "benchmark-key")
	plainText := []byte("benchmark plaintext")

	b.ResetTimer()

	for b.Loop() {
		_, _ = cipher.EncryptBytes(plainText)
	}
}

func BenchmarkDecryptBytes(b *testing.B) {
	cipher := newCipher(b, "benchmark-key")
	plainText := []byte("benchmark plaintext")
	encrypted, _ := cipher.EncryptBytes(plainText)

	b.ResetTimer()

	for b.Loop() {
		_, _ = cipher.DecryptBytes(encrypted)
	}
}

func BenchmarkRoundTrip(b *testing.B) {
	cipher := newCipher(b, "benchmark-key")
	plainText := []byte("benchmark plaintext")

	b.ResetTimer()

	for b.Loop() {
		encrypted, _ := cipher.EncryptBytes(plainText)
		_, _ = cipher.DecryptBytes(encrypted)
	}
}
