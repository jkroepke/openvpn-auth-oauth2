package httphandler_test

import (
	"net/http"
	"net/url"
	"testing"
	"testing/fstest"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/config/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/crypto"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/httphandler"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/generic"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/test/testsuite"
	"github.com/stretchr/testify/require"
)

func TestAssets(t *testing.T) {
	t.Parallel()

	logger := testsuite.NewTestLogger()

	conf := config.Defaults
	conf.OAuth2.Issuer = types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}}
	conf.OAuth2.Endpoints.Discovery = conf.OAuth2.Issuer
	conf.OAuth2.Endpoints.Auth = conf.OAuth2.Issuer
	conf.OAuth2.Endpoints.Token = conf.OAuth2.Issuer
	conf.HTTP.ShortURL = false

	provider, err := generic.NewProvider(t.Context(), conf, http.DefaultClient)
	require.NoError(t, err)

	oAuth2Client, err := oauth2.New(t.Context(), logger.Logger, conf, http.DefaultClient, testsuite.NewFakeStorage(), crypto.New(conf.HTTP.Secret.String()), provider, testsuite.NewFakeOpenVPNClient())
	require.NoError(t, err)

	handler := httphandler.New(conf, oAuth2Client)

	require.HTTPStatusCode(t, handler.ServeHTTP, http.MethodGet, "/", nil, http.StatusNotFound)
	require.HTTPSuccess(t, handler.ServeHTTP, http.MethodGet, "/assets/favicon.svg", nil)
	require.HTTPSuccess(t, handler.ServeHTTP, http.MethodGet, "/assets/i18n/de.json", nil)
}

func TestCustomAssets(t *testing.T) {
	t.Parallel()

	logger := testsuite.NewTestLogger()

	conf := config.Defaults
	conf.OAuth2.Issuer = types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}}
	conf.OAuth2.Endpoints.Discovery = conf.OAuth2.Issuer
	conf.OAuth2.Endpoints.Auth = conf.OAuth2.Issuer
	conf.OAuth2.Endpoints.Token = conf.OAuth2.Issuer
	conf.HTTP.BaseURL.Path = "/custom"

	provider, err := generic.NewProvider(t.Context(), conf, http.DefaultClient)
	require.NoError(t, err)

	oAuth2Client, err := oauth2.New(t.Context(), logger.Logger, conf, http.DefaultClient, testsuite.NewFakeStorage(), crypto.New(conf.HTTP.Secret.String()), provider, testsuite.NewFakeOpenVPNClient())
	require.NoError(t, err)

	conf.HTTP.AssetPath = types.FS{
		FS: fstest.MapFS{
			"index.txt": &fstest.MapFile{
				Data: []byte("index"),
			},
		},
	}

	handler := httphandler.New(conf, oAuth2Client)

	require.HTTPBodyContains(t, handler.ServeHTTP, http.MethodGet, "/custom/assets/index.txt", nil, "index")
}
