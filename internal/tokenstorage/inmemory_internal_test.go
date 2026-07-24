package tokenstorage

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestInMemoryExpiredLookupPreservesConcurrentRefresh(t *testing.T) {
	t.Parallel()

	const clientID = "client"

	ctx := t.Context()
	tokenStorage := NewInMemory("test-secret", time.Hour)

	t.Cleanup(func() {
		require.NoError(t, tokenStorage.Close())
	})

	require.NoError(t, tokenStorage.Set(ctx, clientID, "expired"))

	tokenStorage.mu.Lock()
	expired := tokenStorage.data[clientID]
	expired.Expires = time.Now().Add(-time.Hour)
	tokenStorage.data[clientID] = expired
	tokenStorage.mu.Unlock()

	expiredLookupTime := time.Now()

	require.NoError(t, tokenStorage.Set(ctx, clientID, "refreshed"))
	tokenStorage.deleteExpired(clientID, expiredLookupTime)

	token, err := tokenStorage.Get(ctx, clientID)
	require.NoError(t, err)
	require.Equal(t, "refreshed", token)
}
