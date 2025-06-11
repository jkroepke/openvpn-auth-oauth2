package tokenstorage_test

import (
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/tokenstorage"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStorage_InMemory(t *testing.T) {
	t.Parallel()

	tokenStorage := tokenstorage.NewInMemory(testutils.Secret, time.Millisecond*400)

	t.Cleanup(func() {
		require.NoError(t, tokenStorage.Close())
	})

	require.NoError(t, tokenStorage.Set("0", "TEST0"))
	require.NoError(t, tokenStorage.Set("1", "TEST1"))

	token, err := tokenStorage.Get("0")

	require.NoError(t, err)
	assert.Equal(t, "TEST0", token)

	token, err = tokenStorage.Get("1")

	require.NoError(t, err)
	assert.Equal(t, "TEST1", token)

	token, err = tokenStorage.Get("1")

	require.NoError(t, err)
	assert.Equal(t, "TEST1", token)

	_, err = tokenStorage.Get("2")
	require.ErrorIs(t, err, tokenstorage.ErrNotExists)

	err = tokenStorage.Delete("1")
	require.NoError(t, err)

	_, err = tokenStorage.Get("1")
	require.Error(t, err)
	require.ErrorIs(t, err, tokenstorage.ErrNotExists)
}

func TestStorageExpire_InMemory(t *testing.T) {
	t.Parallel()

	tokenStorage := tokenstorage.NewInMemory(testutils.Secret, 0)

	t.Cleanup(func() {
		require.NoError(t, tokenStorage.Close())
	})

	require.NoError(t, tokenStorage.Set("0", "TEST0"))
	require.NoError(t, tokenStorage.Set("1", "TEST1"))

	_, err := tokenStorage.Get("0")
	require.ErrorIs(t, err, tokenstorage.ErrNotExists)

	_, err = tokenStorage.Get("1")
	require.ErrorIs(t, err, tokenstorage.ErrNotExists)
}
