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

func TestStorage(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	tokenStorage := tokenstorage.NewInMemory(ctx, testutils.Secret, time.Millisecond*400)
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

	tokenStorage.Delete("1")

	_, err = tokenStorage.Get("1")
	require.Error(t, err)
	require.ErrorIs(t, err, tokenstorage.ErrNotExists)
}
