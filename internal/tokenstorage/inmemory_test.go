package tokenstorage_test

import (
	"context"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/tokenstorage"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStorageInMemory(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	tokenStorage := tokenstorage.NewInMemory(testutils.Secret, time.Millisecond*400)

	t.Cleanup(func() {
		require.NoError(t, tokenStorage.Close())
	})

	require.NoError(t, tokenStorage.Set(ctx, "0", "TEST0"))
	require.NoError(t, tokenStorage.Set(ctx, "1", "TEST1"))

	token, err := tokenStorage.Get(ctx, "0")

	require.NoError(t, err)
	assert.Equal(t, "TEST0", token)

	token, err = tokenStorage.Get(ctx, "1")

	require.NoError(t, err)
	assert.Equal(t, "TEST1", token)

	token, err = tokenStorage.Get(ctx, "1")

	require.NoError(t, err)
	assert.Equal(t, "TEST1", token)

	_, err = tokenStorage.Get(ctx, "2")
	require.ErrorIs(t, err, tokenstorage.ErrNotExists)

	err = tokenStorage.Delete(ctx, "1")
	require.NoError(t, err)

	_, err = tokenStorage.Get(ctx, "1")
	require.Error(t, err)
	require.ErrorIs(t, err, tokenstorage.ErrNotExists)
}

func TestStorageInMemory_Expire(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	tokenStorage := tokenstorage.NewInMemory(testutils.Secret, 0)

	t.Cleanup(func() {
		require.NoError(t, tokenStorage.Close())
	})

	require.NoError(t, tokenStorage.Set(ctx, "0", "TEST0"))
	require.NoError(t, tokenStorage.Set(ctx, "1", "TEST1"))

	_, err := tokenStorage.Get(ctx, "0")
	require.ErrorIs(t, err, tokenstorage.ErrNotExists)

	_, err = tokenStorage.Get(ctx, "1")
	require.ErrorIs(t, err, tokenstorage.ErrNotExists)
}

func TestStorageInMemory_InvalidSecret(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	key := "invalid"

	tokenStorage := tokenstorage.NewInMemory(key, time.Second)

	t.Cleanup(func() {
		require.NoError(t, tokenStorage.Close())
	})

	// Salsa20 with SHA256-derived keys accepts any key length.
	// Test that encryption/decryption works even with short keys.
	require.NoError(t, tokenStorage.Set(ctx, "0", "TEST0"))
	token, err := tokenStorage.Get(ctx, "0")
	require.NoError(t, err)
	require.Equal(t, "TEST0", token)
}

func TestStorageInMemory_InvalidData(t *testing.T) {
	t.Parallel()

	tokenStorage := tokenstorage.NewInMemory(testutils.Secret, 0)

	t.Cleanup(func() {
		require.NoError(t, tokenStorage.Close())
	})

	require.ErrorIs(t, tokenStorage.SetStorage(nil), tokenstorage.ErrNilData)
}

func TestStorageInMemory_GarbageCollection(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	// Use short expiration and GC interval for testing
	tokenStorage := tokenstorage.NewInMemoryWithGC(testutils.Secret, 50*time.Millisecond, 100*time.Millisecond)

	t.Cleanup(func() {
		require.NoError(t, tokenStorage.Close())
	})

	// Add tokens
	require.NoError(t, tokenStorage.Set(ctx, "0", "TEST0"))
	require.NoError(t, tokenStorage.Set(ctx, "1", "TEST1"))

	// Wait for tokens to expire and GC to run
	time.Sleep(200 * time.Millisecond)
}

func TestStorageInMemory_NoGC(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	// Disable GC by passing 0 interval
	tokenStorage := tokenstorage.NewInMemoryWithGC(testutils.Secret, 50*time.Millisecond, 0)

	t.Cleanup(func() {
		require.NoError(t, tokenStorage.Close())
	})

	require.NoError(t, tokenStorage.Set(ctx, "0", "TEST0"))

	// Wait for token to expire
	time.Sleep(100 * time.Millisecond)

	// Access should trigger removal
	_, err := tokenStorage.Get(ctx, "0")
	require.ErrorIs(t, err, tokenstorage.ErrNotExists)
}
