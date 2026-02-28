package testsuite

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
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
	"unicode"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/config/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/httphandler"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/generic"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/github"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/google"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/tokenstorage"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
	"github.com/stretchr/testify/require"
	oidcstorage "github.com/zitadel/oidc/v3/example/server/storage"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/net/nettest"
	"golang.org/x/text/language"
)

//nolint:gochecknoglobals
var (
	HashSecret         = sha256.Sum256([]byte(Secret))
	SupportedUILocales = []language.Tag{language.English}
)

type Suite struct {
	managementInterface           net.Listener
	managementInterfaceConn       net.Conn
	logger                        *Logger
	httpClient                    *http.Client
	managementInterfaceConnReader *bufio.Reader
	conf                          config.Config
}

func New(conf config.Config, rt http.RoundTripper) *Suite {
	if rt == nil {
		rt = http.DefaultTransport
	}

	return &Suite{
		conf:       conf,
		logger:     NewTestLogger(),
		httpClient: &http.Client{Transport: NewMockRoundTripper(utils.NewUserAgentTransport(rt))},
	}
}

// SetupMockEnvironment sets up an OpenVPN management interface and a mock OIDC
// provider. It returns the adjusted configuration and helper instances used in
// tests.
func (s *Suite) SetupMockEnvironment(ctx context.Context, tb testing.TB, opConf *op.Config) <-chan error {
	tb.Helper()

	s.managementInterface = s.CreateTCPListener(tb)

	tb.Cleanup(func() {
		require.NoError(tb, s.managementInterface.Close())
	})

	// clientListener must not be closed because it is used by the httpClientListener.
	clientListener, err := nettest.NewLocalListener("tcp")
	require.NoError(tb, err)

	_, resourceServerURL, clientCredentials := s.SetupOIDCServer(tb, clientListener, opConf)

	s.conf.HTTP.BaseURL = types.URL{URL: &url.URL{Scheme: "http", Host: clientListener.Addr().String()}}

	if s.conf.HTTP.Secret == "" {
		s.conf.HTTP.Secret = Secret
	}

	if s.conf.HTTP.AssetPath.IsEmpty() {
		s.conf.HTTP.AssetPath = config.Defaults.HTTP.AssetPath
	}

	if s.conf.HTTP.Template.IsEmpty() {
		s.conf.HTTP.Template = config.Defaults.HTTP.Template
	}

	if s.conf.OpenVPN.ClientConfig.Path.IsEmpty() {
		s.conf.OpenVPN.ClientConfig.Path = config.Defaults.OpenVPN.ClientConfig.Path
	}

	s.conf.OpenVPN.Addr = types.URL{URL: &url.URL{Scheme: s.managementInterface.Addr().Network(), Host: s.managementInterface.Addr().String()}}

	if s.conf.OpenVPN.Bypass.CommonNames == nil {
		s.conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
	}

	s.conf.OAuth2.Issuer = resourceServerURL
	s.conf.OAuth2.Nonce = true                                  // enable nonce for mock testing
	s.conf.OAuth2.RefreshNonce = config.OAuth2RefreshNonceEmpty // use empty nonce for refresh to avoid mock issues

	if s.conf.OAuth2.Client.ID == "" {
		s.conf.OAuth2.Client.ID = clientCredentials.ID
	}

	if s.conf.OAuth2.Client.Secret.String() == "" {
		s.conf.OAuth2.Client.Secret = clientCredentials.Secret
	}

	if s.conf.OAuth2.Refresh.Expires.String() == "" {
		s.conf.OAuth2.Refresh.Expires = time.Hour
	}

	tokenStorage := tokenstorage.NewInMemory(Secret, s.conf.OAuth2.Refresh.Expires)

	oAuth2Client, openVPNClient := s.SetupOpenVPNOAuth2Clients(ctx, tb, tokenStorage)

	httpHandler := httphandler.New(s.conf, oAuth2Client)
	httpClientListener := httptest.NewUnstartedServer(httpHandler)
	require.NoError(tb, httpClientListener.Listener.Close())

	httpClientListener.Listener = clientListener
	httpClientListener.Start()
	tb.Cleanup(httpClientListener.Close)

	httpClientListenerClient := httpClientListener.Client()
	httpClientListenerClient.Transport = s.httpClient.Transport

	jar, err := cookiejar.New(nil)
	require.NoError(tb, err)

	httpClientListenerClient.Jar = jar

	s.httpClient = httpClientListenerClient

	errOpenVPNClientCh := s.ConnectToManagementInterface(tb, openVPNClient)
	require.NoError(tb, err)

	return errOpenVPNClientCh
}

// SetupOIDCServer starts a minimal OIDC server used for integration tests.
func (s *Suite) SetupOIDCServer(tb testing.TB, clientListener net.Listener, opConfig *op.Config) (*httptest.Server, types.URL, config.OAuth2Client) {
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
			CryptoKey:                HashSecret,
			DefaultLogoutRedirectURI: "/",
			CodeMethodS256:           true,
			AuthMethodPost:           true,
			AuthMethodPrivateKeyJWT:  true,
			GrantTypeRefreshToken:    true,
			RequestObjectSupported:   true,
			SupportedUILocales:       SupportedUILocales,
			// SupportedScopes:          []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile, oauth2types.ScopeOfflineAccess},
		}
	}

	opOpts := make([]op.Option, 0, 2)
	opOpts = append(opOpts, op.WithAllowInsecure())
	opOpts = append(opOpts, op.WithLogger(s.logger.Logger))

	opProvider, err := op.NewProvider(opConfig, opStorage, op.IssuerFromHost(""), opOpts...)
	require.NoError(tb, err, s.logger.String())

	httpHandler := http.NewServeMux()
	httpHandler.Handle("/", opProvider)
	httpHandler.Handle("/login/username", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = opStorage.CheckUsernamePassword("test-user@localhost", "verysecure", r.FormValue("authRequestID"))
		http.Redirect(w, r, op.AuthCallbackURL(opProvider)(r.Context(), r.FormValue("authRequestID")), http.StatusFound)
	}))
	httpHandler.Handle(opProvider.UserinfoEndpoint().Relative(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wMock := httptest.NewRecorder()

		opProvider.ServeHTTP(wMock, r)

		if wMock.Code != http.StatusOK {
			http.Error(w, wMock.Body.String(), wMock.Code)

			return
		}

		userInfo := wMock.Body.String()

		var userInfoMap map[string]any
		if err := json.Unmarshal([]byte(userInfo), &userInfoMap); err != nil {
			http.Error(w, "Invalid user info JSON", http.StatusInternalServerError)

			return
		}

		userInfoMap["groups"] = []string{"group1", "group2"}

		updatedUserInfo, err := json.Marshal(userInfoMap)
		if err != nil {
			http.Error(w, "Failed to marshal user info JSON", http.StatusInternalServerError)

			return
		}

		w.WriteHeader(wMock.Code)
		_, _ = w.Write(updatedUserInfo)
	}))

	resourceServer := s.CreateHTTPTestServer(tb, httpHandler)

	resourceServerURL, err := types.NewURL(resourceServer.URL)
	require.NoError(tb, err, s.logger.String())

	return resourceServer, resourceServerURL, config.OAuth2Client{ID: client.GetID(), Secret: types.Secret(clientSecret)}
}

// SetupOpenVPNOAuth2Clients creates mocked OpenVPN and OAuth2 clients using the
// provided configuration.
func (s *Suite) SetupOpenVPNOAuth2Clients(ctx context.Context, tb testing.TB, tokenStorage tokenstorage.Storage) (*oauth2.Client, *openvpn.Client) {
	tb.Helper()

	var (
		err      error
		provider oauth2.Provider
	)

	if s.conf.OAuth2.Provider == "" {
		s.conf.OAuth2.Provider = generic.Name
	}

	if s.conf.OAuth2.Issuer.IsEmpty() {
		s.conf.OAuth2.Issuer = types.URL{URL: &url.URL{Scheme: "http", Host: "example.com"}}
		s.conf.OAuth2.Endpoints.Auth = types.URL{URL: &url.URL{Scheme: "http", Host: "example.com", Path: "/auth"}}
		s.conf.OAuth2.Endpoints.Token = types.URL{URL: &url.URL{Scheme: "http", Host: "example.com", Path: "/token"}}
	}

	switch s.conf.OAuth2.Provider {
	case generic.Name:
		provider, err = generic.NewProvider(ctx, s.conf, s.httpClient)
	case github.Name:
		provider, err = github.NewProvider(ctx, s.conf, s.httpClient)
	case google.Name:
		provider, err = google.NewProvider(ctx, s.conf, s.httpClient)
	default:
		tb.Fatal("unknown oauth2 provider: " + s.conf.OAuth2.Provider)
	}

	require.NoError(tb, err)

	openVPNClient := openvpn.New(s.logger.Logger, s.conf)
	oAuth2Client, err := oauth2.New(ctx, s.logger.Logger, s.conf, s.httpClient, tokenStorage, provider, openVPNClient)
	require.NoError(tb, err)

	openVPNClient.SetOAuth2Client(oAuth2Client)

	tb.Cleanup(func() {
		openVPNClient.Shutdown(ctx)
	})

	return oAuth2Client, openVPNClient
}

// ConnectToManagementInterface establishes a connection to the given management
// interface and returns the accepted net.Conn and an error channel for the
// OpenVPN client.
func (s *Suite) ConnectToManagementInterface(tb testing.TB, openVPNClient *openvpn.Client) <-chan error {
	tb.Helper()

	errOpenVPNClientCh := make(chan error, 1)
	errTCPAcceptCh := make(chan error, 1)

	var err error

	go func(errCh chan<- error) {
		s.managementInterfaceConn, err = s.managementInterface.Accept()

		errCh <- err
	}(errTCPAcceptCh)

	go func(errCh chan<- error) {
		errCh <- openVPNClient.Connect(tb.Context())
	}(errOpenVPNClientCh)

	if err := <-errTCPAcceptCh; err != nil {
		require.NoError(tb, err, "error accepting connection to management interface: %s", s.logger.String())
	}

	select {
	case err := <-errOpenVPNClientCh:
		require.NoError(tb, err, "error connecting OpenVPN client: %s", s.logger.String())
	default:
	}

	require.NotNil(tb, s.managementInterfaceConn, "expected a connection to the management interface, but got nil. Logs: %s", s.logger.String())

	s.managementInterfaceConnReader = bufio.NewReader(s.managementInterfaceConn)

	return errOpenVPNClientCh
}

// SendAndExpectMessage sends a message and immediately validates the response.
func (s *Suite) SendAndExpectMessage(tb testing.TB, sendMessage, expectMessage string) {
	tb.Helper()

	s.SendMessagef(tb, sendMessage)
	s.ExpectMessage(tb, expectMessage)
}

// SendMessagef sends a formatted string to the management interface connection.
func (s *Suite) SendMessagef(tb testing.TB, sendMessage string, args ...any) {
	tb.Helper()

	require.NotNil(tb, s.managementInterfaceConn, "connection is nil")
	require.NoError(tb, s.managementInterfaceConn.SetWriteDeadline(time.Now().Add(time.Second*5)))

	if sendMessage != "ENTER PASSWORD:" {
		sendMessage += "\r\n"
	}

	_, err := fmt.Fprintf(s.managementInterfaceConn, sendMessage, args...)
	require.NoError(tb, err, "error sending message to management interface: %s", s.logger.String())
}

// ExpectMessage reads from the connection and compares the output with the
// expected message.
func (s *Suite) ExpectMessage(tb testing.TB, expectMessage string) {
	tb.Helper()

	var (
		err  error
		line string
	)
	for expected := range strings.SplitSeq(strings.TrimSpace(expectMessage), "\n") {
		err = s.managementInterfaceConn.SetReadDeadline(time.Now().Add(time.Second * 5))
		require.NoError(tb, err, "expected line: %s\nexpected message:\n%s\n\n%s", expected, expectMessage, s.logger.String())

		line, err = s.managementInterfaceConnReader.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			require.NoError(tb, err, "expected line: %s\nexpected message:\n%s\n\n%s", expected, expectMessage, s.logger.String())
		}

		require.Equal(tb, strings.TrimRightFunc(expected, unicode.IsSpace), strings.TrimRightFunc(line, unicode.IsSpace), s.logger.String())
	}
}
