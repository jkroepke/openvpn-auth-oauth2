package httphandler_test

import (
	"net/http"
	"net/url"
	"testing"
	"testing/fstest"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/config/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/httphandler"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/generic"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils/testutils"
	"github.com/stretchr/testify/require"
)

func TestAssets(t *testing.T) {
	t.Parallel()

	logger := testutils.NewTestLogger()

	conf := config.Defaults
	conf.OAuth2.Issuer = types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}}
	conf.OAuth2.Endpoints.Discovery = types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}}
	conf.OAuth2.Endpoints.Auth = types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}}
	conf.OAuth2.Endpoints.Token = types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}}

	provider, err := generic.NewProvider(t.Context(), conf, http.DefaultClient)
	require.NoError(t, err)

	oAuth2Client, err := oauth2.New(t.Context(), logger.Logger, conf, http.DefaultClient, testutils.NewFakeStorage(), provider, testutils.NewFakeOpenVPNClient())
	require.NoError(t, err)

	handler := httphandler.New(conf, oAuth2Client)

	require.HTTPSuccess(t, handler.ServeHTTP, http.MethodGet, "/assets/favicon.svg", nil)
	require.HTTPSuccess(t, handler.ServeHTTP, http.MethodGet, "/assets/i18n/de.json", nil)
}

func TestCustomAssets(t *testing.T) {
	t.Parallel()

	logger := testutils.NewTestLogger()

	conf := config.Defaults
	conf.OAuth2.Issuer = types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}}
	conf.OAuth2.Endpoints.Discovery = types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}}
	conf.OAuth2.Endpoints.Auth = types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}}
	conf.OAuth2.Endpoints.Token = types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}}

	provider, err := generic.NewProvider(t.Context(), conf, http.DefaultClient)
	require.NoError(t, err)

	oAuth2Client, err := oauth2.New(t.Context(), logger.Logger, conf, http.DefaultClient, testutils.NewFakeStorage(), provider, testutils.NewFakeOpenVPNClient())
	require.NoError(t, err)

	conf.HTTP.AssetPath = types.FS{
		FS: fstest.MapFS{
			"index.txt": &fstest.MapFile{
				Data: []byte("index"),
			},
		},
	}

	handler := httphandler.New(conf, oAuth2Client)

	require.HTTPBodyContains(t, handler.ServeHTTP, http.MethodGet, "/assets/index.txt", nil, "index")
}
