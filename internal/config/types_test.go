package config_test

import (
	"encoding/json"
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

	_, err = config.OpenVPNCommonNameMode(-1).MarshalText()

	require.Error(t, err)
}

func TestCNModeString(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "plain", config.CommonNameModePlain.String())
	assert.Equal(t, "omit", config.CommonNameModeOmit.String())

	assert.Panics(t, func() { _ = config.OpenVPNCommonNameMode(-1).String() }, "The code did not panic")
}

func TestOpenVPNConfigStrategyUnmarshalText(t *testing.T) {
	t.Parallel()

	var strategy config.OpenVPNConfigStrategy

	require.NoError(t, strategy.UnmarshalText([]byte("")))
	assert.Equal(t, config.OpenVPNConfigStrategyMerge, strategy)

	require.NoError(t, strategy.UnmarshalText([]byte("merge")))
	assert.Equal(t, config.OpenVPNConfigStrategyMerge, strategy)

	require.NoError(t, strategy.UnmarshalText([]byte("user-selector")))
	assert.Equal(t, config.OpenVPNConfigStrategyUserSelector, strategy)

	require.Error(t, strategy.UnmarshalText([]byte("selector")))
	require.Error(t, strategy.UnmarshalText([]byte("single")))
}

func TestOpenVPNConfigStrategyMarshalText(t *testing.T) {
	t.Parallel()

	strategy, err := config.OpenVPNConfigStrategyMerge.MarshalText()

	require.NoError(t, err)
	assert.Equal(t, []byte("merge"), strategy)

	strategy, err = config.OpenVPNConfigStrategyUserSelector.MarshalText()

	require.NoError(t, err)
	assert.Equal(t, []byte("user-selector"), strategy)

	_, err = config.OpenVPNConfigStrategy(-1).MarshalText()

	require.Error(t, err)
}

func TestOpenVPNConfigStrategyString(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "merge", config.OpenVPNConfigStrategyMerge.String())
	assert.Equal(t, "user-selector", config.OpenVPNConfigStrategyUserSelector.String())

	assert.Panics(t, func() { _ = config.OpenVPNConfigStrategy(-1).String() }, "The code did not panic")
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

	_, err = config.OAuth2AuthStyle(-1).MarshalText()

	require.Error(t, err)
}

func TestOAuth2AuthStyleString(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "AuthStyleInHeader", config.OAuth2AuthStyle(oauth2.AuthStyleInHeader).String())
	assert.Equal(t, "AuthStyleInParams", config.OAuth2AuthStyle(oauth2.AuthStyleInParams).String())
	assert.Equal(t, "AuthStyleAutoDetect", config.OAuth2AuthStyle(oauth2.AuthStyleAutoDetect).String())

	assert.Panics(t, func() { _ = config.OAuth2AuthStyle(-1).String() }, "The code did not panic")
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

func TestOAuth2RefreshNonceUnmarshalText(t *testing.T) {
	t.Parallel()

	var refreshNonce config.OAuth2RefreshNonce

	require.NoError(t, refreshNonce.UnmarshalText([]byte("auto")))
	assert.Equal(t, config.OAuth2RefreshNonceAuto, refreshNonce)

	require.NoError(t, refreshNonce.UnmarshalText([]byte("empty")))
	assert.Equal(t, config.OAuth2RefreshNonceEmpty, refreshNonce)

	require.NoError(t, refreshNonce.UnmarshalText([]byte("equal")))
	assert.Equal(t, config.OAuth2RefreshNonceEqual, refreshNonce)

	require.Error(t, refreshNonce.UnmarshalText([]byte("unknown")))
}

func TestOAuth2RefreshNonceMarshalText(t *testing.T) {
	t.Parallel()

	refreshNonce, err := config.OAuth2RefreshNonceAuto.MarshalText()

	require.NoError(t, err)
	assert.Equal(t, []byte("auto"), refreshNonce)

	refreshNonce, err = config.OAuth2RefreshNonceEmpty.MarshalText()

	require.NoError(t, err)
	assert.Equal(t, []byte("empty"), refreshNonce)

	refreshNonce, err = config.OAuth2RefreshNonceEqual.MarshalText()

	require.NoError(t, err)
	assert.Equal(t, []byte("equal"), refreshNonce)

	_, err = config.OAuth2RefreshNonce(-1).MarshalText()

	require.Error(t, err)
}

func TestOAuth2RefreshNonceString(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "auto", config.OAuth2RefreshNonceAuto.String())
	assert.Equal(t, "empty", config.OAuth2RefreshNonceEmpty.String())
	assert.Equal(t, "equal", config.OAuth2RefreshNonceEqual.String())

	assert.Panics(t, func() { _ = config.OAuth2RefreshNonce(-1).String() }, "The code did not panic")
}

func TestConfigString(t *testing.T) {
	t.Parallel()

	conf := config.Defaults
	conf.HTTP.Secret = "HTTP_SECRET"
	conf.OpenVPN.Password = "OPENVPN_SECRET"
	conf.OAuth2.Client.Secret = "OAUTH_SECRET"

	body := conf.String()

	require.JSONEq(t, `"***"`, extractJSONValue(t, body, "http", "secret"))
	require.JSONEq(t, `"***"`, extractJSONValue(t, body, "openvpn", "password"))
	require.JSONEq(t, `"***"`, extractJSONValue(t, body, "oauth2", "client", "secret"))
	require.NotContains(t, body, "HTTP_SECRET")
	require.NotContains(t, body, "OPENVPN_SECRET")
	require.NotContains(t, body, "OAUTH_SECRET")
}

func TestHTTPMarshalJSON(t *testing.T) {
	t.Parallel()

	httpConfig := config.Defaults.HTTP
	httpConfig.Secret = "HTTP_SECRET"

	body, err := json.Marshal(httpConfig)
	require.NoError(t, err)

	require.JSONEq(t, `"***"`, extractJSONValue(t, string(body), "secret"))
	require.NotContains(t, string(body), "HTTP_SECRET")
}

func extractJSONValue(t *testing.T, body string, path ...string) string {
	t.Helper()

	var value any
	require.NoError(t, json.Unmarshal([]byte(body), &value))

	for _, key := range path {
		object, ok := value.(map[string]any)
		require.True(t, ok)

		value = object[key]
	}

	encodedValue, err := json.Marshal(value)
	require.NoError(t, err)

	return string(encodedValue)
}
