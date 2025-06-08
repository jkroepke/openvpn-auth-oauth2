package tokenstorage_test

import (
	"os"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/tokenstorage"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStorage_File(t *testing.T) {
	t.Parallel()

	temp, err := os.CreateTemp(t.TempDir(), "test-tokenstorage-")
	require.NoError(t, err)
	require.NoError(t, temp.Close())

	tokenStorage, err := tokenstorage.NewFile(temp.Name(), testutils.Secret, 400*time.Millisecond)
	require.NoError(t, err)

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

func TestStorageCleanup_File(t *testing.T) {
	t.Parallel()

	temp, err := os.CreateTemp(t.TempDir(), "test-tokenstorage-")
	require.NoError(t, err)
	require.NoError(t, temp.Close())

	tokenStorage, err := tokenstorage.NewFile(temp.Name(), testutils.Secret, 0)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, tokenStorage.Close())
	})

	require.NoError(t, tokenStorage.Set("0", "TEST0"))
	require.NoError(t, tokenStorage.Set("1", "TEST1"))

	_, err = tokenStorage.Get("0")
	require.ErrorIs(t, err, tokenstorage.ErrNotExists)

	_, err = tokenStorage.Get("1")
	require.ErrorIs(t, err, tokenstorage.ErrNotExists)
}

func TestStorageLoad_File(t *testing.T) {
	t.Parallel()

	temp, err := os.CreateTemp(t.TempDir(), "test-tokenstorage-")
	require.NoError(t, err)
	require.NoError(t, temp.Close())

	tokenStorage, err := tokenstorage.NewFile(temp.Name(), testutils.Secret, time.Minute)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, tokenStorage.Close())
	})

	require.NoError(t, tokenStorage.Set("0", "TEST0"))
	require.NoError(t, tokenStorage.Set("1", "TEST1"))

	require.NoError(t, tokenStorage.Close())

	tokenStorage, err = tokenstorage.NewFile(temp.Name(), testutils.Secret, time.Minute)
	require.NoError(t, err)

	token, err := tokenStorage.Get("0")

	require.NoError(t, err)
	assert.Equal(t, "TEST0", token)

	token, err = tokenStorage.Get("1")

	require.NoError(t, err)
	assert.Equal(t, "TEST1", token)
}

func TestStorageLoadInvalid_File(t *testing.T) {
	t.Parallel()

	temp, err := os.CreateTemp(t.TempDir(), "test-tokenstorage-")
	require.NoError(t, err)

	tokenStorage, err := tokenstorage.NewFile(temp.Name(), testutils.Secret, time.Minute)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, tokenStorage.Close())
	})

	require.NoError(t, tokenStorage.Set("0", "TEST0"))
	require.NoError(t, tokenStorage.Set("1", "TEST1"))

	require.NoError(t, tokenStorage.Close())

	// Corrupt the file by writing invalid data
	_, err = temp.WriteString("invalid data")
	require.NoError(t, err)
	require.NoError(t, temp.Close())

	tokenStorage, err = tokenstorage.NewFile(temp.Name(), testutils.Secret, time.Minute)
	require.EqualError(t, err, "load data error: decode data error: gob: decoding into local type *tokenstorage.dataMap, received remote type unknown type")
}
