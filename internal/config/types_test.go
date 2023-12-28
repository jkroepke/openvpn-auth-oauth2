package config_test

import (
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCNModeUnmarshalText(t *testing.T) {
	t.Parallel()

	var commonNameMode config.OpenVPNCommonNameMode

	require.NoError(t, commonNameMode.UnmarshalText([]byte("plain")))
	assert.Equal(t, config.CommonNameModePlain, commonNameMode)

	require.NoError(t, commonNameMode.UnmarshalText([]byte("omit")))
	assert.Equal(t, config.CommonNameModeOmit, commonNameMode)

	require.Error(t, commonNameMode.UnmarshalText([]byte("unknown")))
}

func TestCNModeMarshalText(t *testing.T) {
	t.Parallel()

	commonNameMode, err := config.CommonNameModePlain.MarshalText()

	require.NoError(t, err)
	assert.Equal(t, []byte("plain"), commonNameMode)

	commonNameMode, err = config.CommonNameModeOmit.MarshalText()

	require.NoError(t, err)
	assert.Equal(t, []byte("omit"), commonNameMode)
}
