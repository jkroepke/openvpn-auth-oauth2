package tokenstorage_test

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/test/testsuite"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/tokenstorage"
	"github.com/stretchr/testify/require"
)

const (
	benchmarkClientID = "bench-client"
	benchmarkToken    = "refresh-token-with-some-size"
)

func BenchmarkStorageInMemory(b *testing.B) {
	ctx := context.Background()

	b.Run("set", func(b *testing.B) {
		storage := tokenstorage.NewInMemoryWithGC(testsuite.Secret, time.Hour, 0)

		b.Cleanup(func() {
			require.NoError(b, storage.Close())
		})

		b.ReportAllocs()
		b.ResetTimer()

		for b.Loop() {
			if err := storage.Set(ctx, benchmarkClientID, benchmarkToken); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("get", func(b *testing.B) {
		storage := tokenstorage.NewInMemoryWithGC(testsuite.Secret, time.Hour, 0)
		require.NoError(b, storage.Set(ctx, benchmarkClientID, benchmarkToken))

		var tokenValue string

		b.Cleanup(func() {
			require.NoError(b, storage.Close())
		})

		b.ReportAllocs()
		b.ResetTimer()

		for b.Loop() {
			token, err := storage.Get(ctx, benchmarkClientID)
			if err != nil {
				b.Fatal(err)
			}

			tokenValue = token
		}

		_ = tokenValue
	})

	b.Run("delete", func(b *testing.B) {
		storage := tokenstorage.NewInMemoryWithGC(testsuite.Secret, time.Hour, 0)
		clientIDs := make([]string, b.N)

		for idx := range b.N {
			clientIDs[idx] = benchmarkClientID + "-" + strconv.Itoa(idx)

			if err := storage.Set(ctx, clientIDs[idx], benchmarkToken); err != nil {
				b.Fatal(err)
			}
		}

		b.Cleanup(func() {
			require.NoError(b, storage.Close())
		})

		b.ReportAllocs()
		b.ResetTimer()

		for idx := range b.N {
			if err := storage.Delete(ctx, clientIDs[idx]); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("lifecycle", func(b *testing.B) {
		storage := tokenstorage.NewInMemoryWithGC(testsuite.Secret, time.Hour, 0)

		var tokenValue string

		b.Cleanup(func() {
			require.NoError(b, storage.Close())
		})

		b.ReportAllocs()
		b.ResetTimer()

		for b.Loop() {
			if err := storage.Set(ctx, benchmarkClientID, benchmarkToken); err != nil {
				b.Fatal(err)
			}

			token, err := storage.Get(ctx, benchmarkClientID)
			if err != nil {
				b.Fatal(err)
			}

			if err = storage.Delete(ctx, benchmarkClientID); err != nil {
				b.Fatal(err)
			}

			tokenValue = token
		}

		_ = tokenValue
	})
}
