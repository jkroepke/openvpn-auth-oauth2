package storage_test

import (
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStorage(t *testing.T) {
	t.Parallel()

	storageClient := storage.New(time.Millisecond * 400)
	require.NoError(t, storageClient.Set(uint64(0), "TEST0"))
	require.NoError(t, storageClient.Set(uint64(1), "TEST1"))

	token, err := storageClient.Get(uint64(0))

	require.NoError(t, err)
	assert.Equal(t, "TEST0", token)

	token, err = storageClient.Get(uint64(1))

	require.NoError(t, err)
	assert.Equal(t, "TEST1", token)

	_, err = storageClient.Get(uint64(2))
	require.ErrorIs(t, err, storage.ErrNotExists)

	storageClient.Delete(uint64(1))

	_, err = storageClient.Get(uint64(1))
	require.Error(t, err)
	require.ErrorIs(t, err, storage.ErrNotExists)
}
