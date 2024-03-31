package storage_test

import (
	"context"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/storage"
	"github.com/jkroepke/openvpn-auth-oauth2/pkg/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStorage(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	storageClient := storage.New(ctx, testutils.Secret, time.Millisecond*400)
	require.NoError(t, storageClient.Set("0", "TEST0"))
	require.NoError(t, storageClient.Set("1", "TEST1"))

	token, err := storageClient.Get("0")

	require.NoError(t, err)
	assert.Equal(t, "TEST0", token)

	token, err = storageClient.Get("1")

	require.NoError(t, err)
	assert.Equal(t, "TEST1", token)

	_, err = storageClient.Get("2")
	require.ErrorIs(t, err, storage.ErrNotExists)

	storageClient.Delete("1")

	_, err = storageClient.Get("1")
	require.Error(t, err)
	require.ErrorIs(t, err, storage.ErrNotExists)
}
