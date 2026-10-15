package ssf

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReplayCache(t *testing.T) {
	t.Parallel()

	cache := newReplayCache()
	now := time.Unix(1_700_000_000, 0)

	cache.add("a", now.Add(time.Minute), now)
	cache.add("expired", now, now)

	assert.True(t, cache.seen("a", now))
	assert.False(t, cache.seen("b", now))
	assert.False(t, cache.seen("expired", now))
	assert.Equal(t, 1, cache.len())

	later := now.Add(time.Minute)
	assert.False(t, cache.seen("a", later), "an entry expires with the maximum age of its SET")

	cache.add("b", later.Add(time.Minute), later)
	assert.Equal(t, 1, cache.len(), "adding drops expired entries")
	assert.True(t, cache.seen("b", later))
}

func TestReplayCacheAfterMaxAge(t *testing.T) {
	t.Parallel()

	verifier := NewVerifier(VerifierConfig{MaxAge: time.Hour})
	now := time.Unix(1_700_000_000, 0)
	verifier.now = func() time.Time { return now }

	verifier.Processed(Event{ID: "a", IssuedAt: now.Add(-30 * time.Minute)})
	assert.True(t, verifier.replay.seen("a", now))

	// Once the iat is older than the maximum age, the iat check rejects the
	// SET, so the jti is no longer needed.
	assert.False(t, verifier.replay.seen("a", now.Add(30*time.Minute)))
}

func TestNumericDate(t *testing.T) {
	t.Parallel()

	for _, value := range []float64{-1, 1e19} {
		_, err := numericDate(value)
		require.Error(t, err, value)
	}

	date, err := numericDate(1.25)
	require.NoError(t, err)
	assert.Equal(t, time.Unix(1, int64(250*time.Millisecond)), date)
}
