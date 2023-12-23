package testutils

import (
	"bufio"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/generic"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/storage"
	"github.com/stretchr/testify/require"
	oidcStorage "github.com/zitadel/oidc/v3/example/server/storage"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/text/language"
)

const HTTPSecret = "0123456789101112"

func SendLine(tb testing.TB, conn net.Conn, msg string, a ...any) {
	tb.Helper()

	_, err := fmt.Fprintf(conn, msg, a...)
	require.NoError(tb, err)
}

func ReadLine(t *testing.T, reader *bufio.Reader) string {
	t.Helper()

	line, err := reader.ReadString('\n')

	if err != nil && !errors.Is(err, io.EOF) {
		require.NoError(t, err)
	}

	return strings.TrimSpace(line)
}

func SetupResourceServer(clientListener net.Listener) (*httptest.Server, *url.URL, config.OAuth2Client, error) {
	client := oidcStorage.WebClient(
		clientListener.Addr().String(),
		"SECRET",
		fmt.Sprintf("http://%s/oauth2/callback", clientListener.Addr().String()),
	)

	clients := map[string]*oidcStorage.Client{
		clientListener.Addr().String(): client,
	}

	opStorage := oidcStorage.NewStorageWithClients(oidcStorage.NewUserStore("http://localhost"), clients)
	opConfig := &op.Config{
		CryptoKey:                sha256.Sum256([]byte("test")),
		DefaultLogoutRedirectURI: "/",
		CodeMethodS256:           true,
		AuthMethodPost:           true,
		AuthMethodPrivateKeyJWT:  true,
		GrantTypeRefreshToken:    true,
		RequestObjectSupported:   true,
		SupportedUILocales:       []language.Tag{language.English},
	}

	opProvider, err := op.NewProvider(opConfig, opStorage, op.IssuerFromHost(""), op.WithAllowInsecure())
	if err != nil {
		return nil, nil, config.OAuth2Client{}, err //nolint:wrapcheck
	}

	mux := http.NewServeMux()
	mux.Handle("/", opProvider)
	mux.Handle("/login/username", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = opStorage.CheckUsernamePassword("test-user@localhost", "verysecure", r.FormValue("authRequestID"))
		http.Redirect(w, r, op.AuthCallbackURL(opProvider)(r.Context(), r.FormValue("authRequestID")), http.StatusFound)
	}))

	resourceServer := httptest.NewServer(mux)
	resourceServerURL, err := url.Parse(resourceServer.URL)
	if err != nil {
		return nil, nil, config.OAuth2Client{}, err //nolint:wrapcheck
	}

	return resourceServer, resourceServerURL, config.OAuth2Client{ID: clientListener.Addr().String(), Secret: "SECRET"}, err
}

//nolint:cyclop
func SetupMockEnvironment(t *testing.T, conf config.Config) (
	config.Config, *openvpn.Client, net.Listener,
	*oauth2.Provider, *httptest.Server, *http.Client, func(),
) {
	t.Helper()

	logger := NewTestLogger()

	managementInterface := TCPTestListener(t)
	clientListener := TCPTestListener(t)

	resourceServer, resourceServerURL, clientCredentials, err := SetupResourceServer(clientListener)
	require.NoError(t, err)

	if conf.HTTP.BaseURL == nil {
		conf.HTTP.BaseURL = &url.URL{Scheme: "http", Host: clientListener.Addr().String()}
	}

	if conf.HTTP.Secret == "" {
		conf.HTTP.Secret = HTTPSecret
	}

	if conf.HTTP.CallbackTemplate == nil {
		conf.HTTP.CallbackTemplate = config.Defaults.HTTP.CallbackTemplate
	}

	if conf.OpenVpn.Addr == nil {
		conf.OpenVpn.Addr = &url.URL{Scheme: managementInterface.Addr().Network(), Host: managementInterface.Addr().String()}
	}

	if conf.OpenVpn.Bypass.CommonNames == nil {
		conf.OpenVpn.Bypass.CommonNames = make([]string, 0)
	}

	if conf.OAuth2.Issuer == nil {
		conf.OAuth2.Issuer = resourceServerURL
	}

	if conf.OAuth2.Provider == "" {
		conf.OAuth2.Provider = generic.Name
	}

	if conf.OAuth2.Client.ID == "" {
		conf.OAuth2.Client.ID = clientCredentials.ID
	}

	if conf.OAuth2.Client.Secret.String() == "" {
		conf.OAuth2.Client.Secret = clientCredentials.Secret
	}

	if conf.OAuth2.Refresh.Expires.String() == "" {
		conf.OAuth2.Refresh.Expires = time.Hour
	}

	storageClient := storage.New(conf.OAuth2.Refresh.Expires)
	provider := oauth2.New(logger, conf, storageClient)
	openvpnClient := openvpn.NewClient(logger, conf, provider)

	require.NoError(t, provider.Discover(openvpnClient))

	httpClientListener := httptest.NewUnstartedServer(provider.Handler())
	httpClientListener.Listener.Close()
	httpClientListener.Listener = clientListener
	httpClientListener.Start()

	httpClient := httpClientListener.Client()

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	httpClient.Jar = jar

	return conf, openvpnClient, managementInterface, provider, httpClientListener, httpClient, func() {
		defer managementInterface.Close()
		defer clientListener.Close()
		defer resourceServer.Close()
		defer httpClientListener.Close()
	}
}
