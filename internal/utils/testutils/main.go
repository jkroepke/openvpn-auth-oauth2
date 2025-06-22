package testutils

import (
	"bufio"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/config/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/httphandler"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/generic"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/github"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/google"
	oauth2types "github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/tokenstorage"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
	"github.com/stretchr/testify/require"
	oidcstorage "github.com/zitadel/oidc/v3/example/server/storage"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/net/nettest"
	"golang.org/x/text/language"
)

const (
	Password = "password"
	Secret   = "0123456789101112"
)

// ExpectVersionAndReleaseHold performs the initial handshake with the mocked
// management interface. It checks for a version query and hold release.
func ExpectVersionAndReleaseHold(tb testing.TB, conn net.Conn, reader *bufio.Reader) {
	tb.Helper()

	SendMessagef(tb, conn, ">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info")
	SendMessagef(tb, conn, ">HOLD:Waiting for hold release:0")

	var expectedCommand int

	for range 2 {
		line := ReadLine(tb, conn, reader)
		switch line {
		case "hold release":
			SendMessagef(tb, conn, "SUCCESS: hold release succeeded")

			expectedCommand++
		case "version":
			SendMessagef(tb, conn, "OpenVPN Version: OpenVPN Mock\r\nManagement Interface Version: 5\r\nEND")

			expectedCommand++
		default:
			require.Contains(tb, []string{"version", "hold release"}, line)
		}
	}

	require.Equal(tb, 2, expectedCommand)
}

// SendMessagef sends a formatted string to the management interface connection.
func SendMessagef(tb testing.TB, conn net.Conn, sendMessage string, args ...any) {
	tb.Helper()

	require.NotNil(tb, conn, "connection is nil")
	require.NoError(tb, conn.SetWriteDeadline(time.Now().Add(time.Second*5)))

	if sendMessage != "ENTER PASSWORD:" {
		sendMessage += "\r\n"
	}

	_, err := fmt.Fprintf(conn, sendMessage, args...)
	require.NoError(tb, err)
}

// ExpectMessage reads from the connection and compares the output with the
// expected message.
func ExpectMessage(tb testing.TB, conn net.Conn, reader *bufio.Reader, expectMessage string) {
	tb.Helper()

	var (
		err  error
		line string
	)

	for _, expected := range strings.Split(strings.TrimSpace(expectMessage), "\n") {
		err = conn.SetReadDeadline(time.Now().Add(time.Second * 5))
		require.NoError(tb, err, "expected line: %s\nexpected message:\n%s", expected, expectMessage)

		line, err = reader.ReadString('\n')

		if err != nil && !errors.Is(err, io.EOF) {
			require.NoError(tb, err, "expected line: %s\nexpected message:\n%s", expected, expectMessage)
		}

		require.Equal(tb, strings.TrimRightFunc(expected, unicode.IsSpace), strings.TrimRightFunc(line, unicode.IsSpace))
	}
}

// SendAndExpectMessage sends a message and immediately validates the response.
func SendAndExpectMessage(tb testing.TB, conn net.Conn, reader *bufio.Reader, sendMessage, expectMessage string) {
	tb.Helper()

	SendMessagef(tb, conn, sendMessage)
	ExpectMessage(tb, conn, reader, expectMessage)
}

// ReadLine reads a single line from the connection with a timeout.
func ReadLine(tb testing.TB, conn net.Conn, reader *bufio.Reader) string {
	tb.Helper()

	err := conn.SetReadDeadline(time.Now().Add(time.Second * 50))
	require.NoError(tb, err)

	line, err := reader.ReadString('\n')

	if err != nil && !errors.Is(err, io.EOF) {
		require.NoError(tb, err)
	}

	return strings.TrimRightFunc(line, unicode.IsSpace)
}

// SetupResourceServer starts a minimal OIDC server used for integration tests.
func SetupResourceServer(tb testing.TB, clientListener net.Listener, logger *slog.Logger, opConfig *op.Config) (
	*httptest.Server, types.URL, config.OAuth2Client, error,
) {
	tb.Helper()

	clientSecret := Secret

	client := oidcstorage.WebClient(
		clientListener.Addr().String(),
		clientSecret,
		fmt.Sprintf("http://%s/oauth2/callback", clientListener.Addr().String()),
		fmt.Sprintf("https://%s/oauth2/callback", clientListener.Addr().String()),
	)

	clients := map[string]*oidcstorage.Client{
		client.GetID(): client,
	}

	opStorage := oidcstorage.NewStorageWithClients(oidcstorage.NewUserStore("http://localhost"), clients)

	if opConfig == nil {
		opConfig = &op.Config{
			CryptoKey:                sha256.Sum256([]byte(Secret)),
			DefaultLogoutRedirectURI: "/",
			CodeMethodS256:           true,
			AuthMethodPost:           true,
			AuthMethodPrivateKeyJWT:  true,
			GrantTypeRefreshToken:    true,
			RequestObjectSupported:   true,
			SupportedUILocales:       []language.Tag{language.English},
			SupportedScopes:          []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile, oauth2types.ScopeOfflineAccess},
		}
	}

	opOpts := make([]op.Option, 0, 2)
	opOpts = append(opOpts, op.WithAllowInsecure())

	if logger != nil {
		opOpts = append(opOpts, op.WithLogger(logger))
	}

	opProvider, err := op.NewProvider(opConfig, opStorage, op.IssuerFromHost(""), opOpts...)
	if err != nil {
		return nil, types.URL{}, config.OAuth2Client{}, err //nolint:wrapcheck
	}

	mux := http.NewServeMux()
	mux.Handle("/", opProvider)
	mux.Handle("/login/username", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = opStorage.CheckUsernamePassword("test-user@localhost", "verysecure", r.FormValue("authRequestID"))
		http.Redirect(w, r, op.AuthCallbackURL(opProvider)(r.Context(), r.FormValue("authRequestID")), http.StatusFound)
	}))

	resourceServer := httptest.NewServer(mux)

	tb.Cleanup(func() {
		resourceServer.Close()
	})

	resourceServerURL, err := types.NewURL(resourceServer.URL)
	if err != nil {
		return nil, types.URL{}, config.OAuth2Client{}, err //nolint:wrapcheck
	}

	return resourceServer, resourceServerURL, config.OAuth2Client{ID: client.GetID(), Secret: types.Secret(clientSecret)}, nil
}

// SetupMockEnvironment sets up an OpenVPN management interface and a mock OIDC
// provider. It returns the adjusted configuration and helper instances used in
// tests.
func SetupMockEnvironment(ctx context.Context, tb testing.TB, conf config.Config, rt http.RoundTripper, opConf *op.Config) (
	config.Config, *openvpn.Client, net.Listener, *oauth2.Client, *httptest.Server, *http.Client, *Logger,
) {
	tb.Helper()

	logger := NewTestLogger()

	managementInterface, err := nettest.NewLocalListener("tcp")
	require.NoError(tb, err)

	tb.Cleanup(func() {
		require.NoError(tb, managementInterface.Close())
	})

	// clientListener must not be closed, because it is used by the httpClientListener.
	clientListener, err := nettest.NewLocalListener("tcp")
	require.NoError(tb, err)

	_, resourceServerURL, clientCredentials, err := SetupResourceServer(tb, clientListener, logger.Logger, opConf)
	require.NoError(tb, err)

	conf.HTTP.BaseURL = types.URL{URL: &url.URL{Scheme: "http", Host: clientListener.Addr().String()}}

	if conf.HTTP.Secret == "" {
		conf.HTTP.Secret = Secret
	}

	if conf.HTTP.AssetPath.IsEmpty() {
		conf.HTTP.AssetPath = config.Defaults.HTTP.AssetPath
	}

	if conf.HTTP.Template.IsEmpty() {
		conf.HTTP.Template = config.Defaults.HTTP.Template
	}

	if conf.OpenVPN.ClientConfig.Path.IsEmpty() {
		conf.OpenVPN.ClientConfig.Path = config.Defaults.OpenVPN.ClientConfig.Path
	}

	conf.OpenVPN.Addr = types.URL{URL: &url.URL{Scheme: managementInterface.Addr().Network(), Host: managementInterface.Addr().String()}}

	if conf.OpenVPN.Bypass.CommonNames == nil {
		conf.OpenVPN.Bypass.CommonNames = make([]string, 0)
	}

	conf.OAuth2.Issuer = resourceServerURL
	conf.OAuth2.Nonce = false // not supported by the mock

	if conf.OAuth2.Client.ID == "" {
		conf.OAuth2.Client.ID = clientCredentials.ID
	}

	if conf.OAuth2.Client.Secret.String() == "" {
		conf.OAuth2.Client.Secret = clientCredentials.Secret
	}

	if conf.OAuth2.Refresh.Expires.String() == "" {
		conf.OAuth2.Refresh.Expires = time.Hour
	}

	httpClient := &http.Client{Transport: NewMockRoundTripper(utils.NewUserAgentTransport(rt))}
	tokenStorage := tokenstorage.NewInMemory(Secret, conf.OAuth2.Refresh.Expires)

	oAuth2Client, openvpnClient := SetupOpenVPNOAuth2Clients(ctx, tb, conf, logger.Logger, httpClient, tokenStorage)

	httpHandler := httphandler.New(conf, oAuth2Client)
	httpClientListener := httptest.NewUnstartedServer(httpHandler)
	require.NoError(tb, httpClientListener.Listener.Close())

	httpClientListener.Listener = clientListener
	httpClientListener.Start()
	tb.Cleanup(httpClientListener.Close)

	httpClientListenerClient := httpClientListener.Client()
	httpClientListenerClient.Transport = httpClient.Transport

	jar, err := cookiejar.New(nil)
	require.NoError(tb, err)

	httpClientListenerClient.Jar = jar

	return conf, openvpnClient, managementInterface, oAuth2Client, httpClientListener, httpClientListenerClient, logger
}

// SetupOpenVPNOAuth2Clients creates mocked OpenVPN and OAuth2 clients using the
// provided configuration.
func SetupOpenVPNOAuth2Clients(
	ctx context.Context, tb testing.TB, conf config.Config, logger *slog.Logger, httpClient *http.Client, tokenStorage tokenstorage.Storage,
) (*oauth2.Client, *openvpn.Client) {
	tb.Helper()

	var (
		err      error
		provider oauth2.Provider
	)

	if conf.OAuth2.Provider == "" {
		conf.OAuth2.Provider = generic.Name
	}

	if conf.OAuth2.Issuer.IsEmpty() {
		conf.OAuth2.Issuer = types.URL{URL: &url.URL{Scheme: "http", Host: "example.com"}}
		conf.OAuth2.Endpoints.Auth = types.URL{URL: &url.URL{Scheme: "http", Host: "example.com", Path: "/auth"}}
		conf.OAuth2.Endpoints.Token = types.URL{URL: &url.URL{Scheme: "http", Host: "example.com", Path: "/token"}}
	}

	switch conf.OAuth2.Provider {
	case generic.Name:
		provider, err = generic.NewProvider(ctx, conf, httpClient)
	case github.Name:
		provider, err = github.NewProvider(ctx, conf, httpClient)
	case google.Name:
		provider, err = google.NewProvider(ctx, conf, httpClient)
	default:
		tb.Fatal("unknown oauth2 provider: " + conf.OAuth2.Provider)
	}

	require.NoError(tb, err)

	openVPNClient := openvpn.New(logger, conf)
	oAuth2Client, err := oauth2.New(ctx, logger, conf, httpClient, tokenStorage, provider, openVPNClient)
	require.NoError(tb, err)

	openVPNClient.SetOAuth2Client(oAuth2Client)

	tb.Cleanup(openVPNClient.Shutdown)

	return oAuth2Client, openVPNClient
}

// ConnectToManagementInterface establishes a connection to the given management
// interface and returns the accepted net.Conn and an error channel for the
// OpenVPN client.
func ConnectToManagementInterface(tb testing.TB, managementInterface net.Listener, openVPNClient *openvpn.Client) (net.Conn, <-chan error, error) {
	tb.Helper()

	errOpenVPNClientCh := make(chan error, 1)
	errTCPAcceptCh := make(chan error, 1)

	var (
		conn net.Conn
		err  error
	)

	go func(errCh chan<- error) {
		conn, err = managementInterface.Accept()

		errCh <- err
	}(errTCPAcceptCh)

	go func(errCh chan<- error) {
		errCh <- openVPNClient.Connect(tb.Context())
	}(errOpenVPNClientCh)

	if err := <-errTCPAcceptCh; err != nil {
		return nil, nil, fmt.Errorf("error accepting connection: %w", err)
	}

	select {
	case err := <-errOpenVPNClientCh:
		return nil, nil, fmt.Errorf("error connecting to management interface: %w", err)
	default:
	}

	if conn == nil {
		return nil, nil, errors.New("connection is nil")
	}

	return conn, errOpenVPNClientCh, nil
}
