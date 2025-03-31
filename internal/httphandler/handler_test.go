package httphandler_test

import (
	"net/http"
	"testing"
	"testing/fstest"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/httphandler"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/generic"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils/testutils"
	"github.com/stretchr/testify/require"
)

func TestAssets(t *testing.T) {
	logger := testutils.NewTestLogger()

	conf := config.Defaults
	conf.OAuth2.Issuer = &config.URL{Scheme: "http", Host: "localhost"}
	conf.OAuth2.Endpoints.Discovery = &config.URL{Scheme: "http", Host: "localhost"}
	conf.OAuth2.Endpoints.Auth = &config.URL{Scheme: "http", Host: "localhost"}
	conf.OAuth2.Endpoints.Token = &config.URL{Scheme: "http", Host: "localhost"}

	provider, err := generic.NewProvider(t.Context(), conf, http.DefaultClient)
	require.NoError(t, err)

	oAuth2Client, err := oauth2.New(t.Context(), logger.Logger, conf, http.DefaultClient, testutils.NewFakeStorage(), provider, testutils.NewFakeOpenVPNClient())
	require.NoError(t, err)

	assetsFs := fstest.MapFS{
		"index.txt": &fstest.MapFile{
			Data: []byte("index"),
		},
	}
	handler := httphandler.New(config.Defaults, oAuth2Client, assetsFs)

	require.HTTPBodyContains(t, handler.ServeHTTP, http.MethodGet, "/assets/index.txt", nil, "index")
}
