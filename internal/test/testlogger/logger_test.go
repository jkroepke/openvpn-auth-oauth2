package testlogger_test

import (
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/test/testlogger"
	"github.com/stretchr/testify/require"
)

func TestLogger(t *testing.T) {
	t.Parallel()

	t.Run("buffered", func(t *testing.T) {
		t.Parallel()

		logger := testlogger.New()
		logger.Logger().Info("test message")

		require.Contains(t, logger.String(), "test message")
	})

	t.Run("discard", func(t *testing.T) {
		t.Parallel()

		logger := testlogger.NewDiscard()
		logger.Logger().Info("test message")

		require.Empty(t, logger.String())
	})
}
