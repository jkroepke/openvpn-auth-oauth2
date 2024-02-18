package config_test

import (
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
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

func TestOAuth2AuthStyleUnmarshalText(t *testing.T) {
	t.Parallel()

	var oAuth2AuthStyle config.OAuth2AuthStyle

	require.NoError(t, oAuth2AuthStyle.UnmarshalText([]byte("AuthStyleInHeader")))
	assert.Equal(t, config.OAuth2AuthStyle(oauth2.AuthStyleInHeader), oAuth2AuthStyle)

	require.NoError(t, oAuth2AuthStyle.UnmarshalText([]byte("AuthStyleInParams")))
	assert.Equal(t, config.OAuth2AuthStyle(oauth2.AuthStyleInParams), oAuth2AuthStyle)

	require.NoError(t, oAuth2AuthStyle.UnmarshalText([]byte("AuthStyleAutoDetect")))
	assert.Equal(t, config.OAuth2AuthStyle(oauth2.AuthStyleAutoDetect), oAuth2AuthStyle)

	require.Error(t, oAuth2AuthStyle.UnmarshalText([]byte("unknown")))
}

func TestOAuth2AuthStyleMarshalText(t *testing.T) {
	t.Parallel()

	oAuth2AuthStyle, err := config.OAuth2AuthStyle(oauth2.AuthStyleInHeader).MarshalText()

	require.NoError(t, err)
	assert.Equal(t, []byte("AuthStyleInHeader"), oAuth2AuthStyle)

	oAuth2AuthStyle, err = config.OAuth2AuthStyle(oauth2.AuthStyleInParams).MarshalText()

	require.NoError(t, err)
	assert.Equal(t, []byte("AuthStyleInParams"), oAuth2AuthStyle)

	oAuth2AuthStyle, err = config.OAuth2AuthStyle(oauth2.AuthStyleAutoDetect).MarshalText()

	require.NoError(t, err)
	assert.Equal(t, []byte("AuthStyleAutoDetect"), oAuth2AuthStyle)
}

func TestOAuth2AuthStyleGetAuthStyle(t *testing.T) {
	t.Parallel()

	oAuth2AuthStyle := config.OAuth2AuthStyle(oauth2.AuthStyleInHeader).AuthStyle()
	assert.Equal(t, oauth2.AuthStyleInHeader, oAuth2AuthStyle)

	oAuth2AuthStyle = config.OAuth2AuthStyle(oauth2.AuthStyleInParams).AuthStyle()
	assert.Equal(t, oauth2.AuthStyleInParams, oAuth2AuthStyle)

	oAuth2AuthStyle = config.OAuth2AuthStyle(oauth2.AuthStyleAutoDetect).AuthStyle()
	assert.Equal(t, oauth2.AuthStyleAutoDetect, oAuth2AuthStyle)
}
