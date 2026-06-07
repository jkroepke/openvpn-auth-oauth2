package testsuite

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/config/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/httphandler"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/generic"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/github"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/google"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/test/testlogger"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/tokenstorage"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
	"github.com/stretchr/testify/require"
	oidcstorage "github.com/zitadel/oidc/v3/example/server/storage"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/net/nettest"
)

type Suite struct {
	managementInterface           net.Listener
	managementInterfaceConn       net.Conn
	rt                            http.RoundTripper
	logger                        *testlogger.Logger
	httpClient                    *http.Client
	httpClientListener            *httptest.Server
	managementInterfaceConnReader *bufio.Reader
	openVPNClient                 *openvpn.Client
	oAuth2Client                  *oauth2.Client
	errOpenVPNClientCh            chan error
	conf                          config.Config
}

func New(conf config.Config, opts ...Options) *Suite {
	suite := &Suite{
		conf:   conf,
		logger: testlogger.New(),
		rt:     http.DefaultTransport,
	}

	for _, opt := range opts {
		if opt != nil {
			opt(suite)
		}
	}

	suite.httpClient = &http.Client{Transport: NewMockRoundTripper(utils.NewUserAgentTransport(suite.rt))}

	return suite
}

// SetupMockEnvironment sets up an OpenVPN management interface and a mock OIDC
// provider. It returns the adjusted configuration and helper instances used in
// tests.
func (s *Suite) SetupMockEnvironment(ctx context.Context, tb testing.TB, opConf *op.Config) <-chan error {
	tb.Helper()

	s.setupManagementInterface(tb)
	s.applyManagementDefaults()

	// clientListener must not be closed because it is used by the httpClientListener.
	clientListener, err := nettest.NewLocalListener("tcp")
	require.NoError(tb, err)

	s.SetupOIDCServer(tb, clientListener, opConf)

	if s.conf.HTTP.AssetPath.IsEmpty() {
		s.conf.HTTP.AssetPath = config.Defaults.HTTP.AssetPath
	}

	if s.conf.HTTP.Template.IsEmpty() {
		s.conf.HTTP.Template = config.Defaults.HTTP.Template
	}

	if s.conf.OpenVPN.ClientConfig.Path.IsEmpty() {
		s.conf.OpenVPN.ClientConfig.Path = config.Defaults.OpenVPN.ClientConfig.Path
	}

	tokenStorage := tokenstorage.NewInMemory(Secret, s.conf.OAuth2.Refresh.Expires)

	s.oAuth2Client, s.openVPNClient = s.SetupOpenVPNOAuth2Clients(ctx, tb, tokenStorage)

	httpHandler := httphandler.New(s.conf, s.oAuth2Client)
	s.httpClientListener = httptest.NewUnstartedServer(httpHandler)
	require.NoError(tb, s.httpClientListener.Listener.Close())

	s.httpClientListener.Listener = clientListener
	s.httpClientListener.Start()
	tb.Cleanup(s.httpClientListener.Close)

	httpClientListenerClient := s.httpClientListener.Client()
	httpClientListenerClient.Transport = s.httpClient.Transport

	jar, err := cookiejar.New(nil)
	require.NoError(tb, err)

	httpClientListenerClient.Jar = jar

	s.httpClient = httpClientListenerClient

	errOpenVPNClientCh := s.connectOpenVPNManagement(ctx, tb)

	listen, err := WaitUntilListening(ctx, tb, s.httpClientListener.Listener.Addr().Network(), s.httpClientListener.Listener.Addr().String())
	require.NoError(tb, err)
	require.NoError(tb, listen.Close())

	return errOpenVPNClientCh
}

// SetupOIDCServer starts a minimal OIDC server used for integration tests.
func (s *Suite) SetupOIDCServer(tb testing.TB, clientListener net.Listener, opConfig *op.Config) (*httptest.Server, types.URL, config.OAuth2Client) {
	tb.Helper()

	clientSecret := Secret

	client := oidcstorage.WebClient(
		"clientID",
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
		}
	}

	opOpts := make([]op.Option, 0, 2)
	opOpts = append(opOpts, op.WithAllowInsecure())
	opOpts = append(opOpts, op.WithLogger(s.logger.Logger()))

	opProvider, err := op.NewProvider(opConfig, opStorage, op.IssuerFromHost(""), opOpts...)
	require.NoError(tb, err, s.Logs())

	httpHandler := http.NewServeMux()
	httpHandler.Handle("/", opProvider)
	httpHandler.Handle("/login/username", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// G120: Parsing form data without limiting request body size can allow memory exhaustion
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

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
	require.NoError(tb, err, s.Logs())

	clientCredentials := config.OAuth2Client{ID: client.GetID(), Secret: types.Secret(clientSecret)}
	s.applyOIDCServerConfig(clientListener, resourceServerURL, clientCredentials)

	return resourceServer, resourceServerURL, clientCredentials
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
		s.conf.OAuth2.Issuer = types.URL{URL: &url.URL{Scheme: config.SchemeHTTP, Host: TestDomain}}
		s.conf.OAuth2.Endpoints.Auth = types.URL{URL: &url.URL{Scheme: config.SchemeHTTP, Host: TestDomain, Path: "/auth"}}
		s.conf.OAuth2.Endpoints.Token = types.URL{URL: &url.URL{Scheme: config.SchemeHTTP, Host: TestDomain, Path: "/token"}}
	}

	if s.conf.OpenVPN.CommandTimeout == 0 {
		s.conf.OpenVPN.CommandTimeout = time.Millisecond * 300
	}

	if tokenStorage == nil {
		refreshExpires := s.conf.OAuth2.Refresh.Expires
		if refreshExpires == 0 {
			refreshExpires = time.Hour
		}

		tokenStorage = tokenstorage.NewInMemory(Secret, refreshExpires)
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

	openVPNClient := openvpn.New(s.logger.Logger(), s.conf)
	oAuth2Client, err := oauth2.New(ctx, s.logger.Logger(), s.conf, s.httpClient, tokenStorage, Cipher, provider, openVPNClient)
	require.NoError(tb, err)

	openVPNClient.SetOAuth2Client(oAuth2Client)

	tb.Cleanup(func() {
		openVPNClient.Shutdown(ctx)
	})

	return oAuth2Client, openVPNClient
}

func (s *Suite) SetupManagementEnvironment(ctx context.Context, tb testing.TB, tokenStorage tokenstorage.Storage) <-chan error {
	tb.Helper()

	s.setupManagementInterface(tb)
	s.applyManagementDefaults()

	if s.conf.HTTP.BaseURL.IsEmpty() {
		s.conf.HTTP.BaseURL = types.URL{URL: &url.URL{Scheme: config.SchemeHTTP, Host: "localhost"}}
	}

	s.oAuth2Client, s.openVPNClient = s.SetupOpenVPNOAuth2Clients(ctx, tb, tokenStorage)

	return s.connectOpenVPNManagement(ctx, tb)
}

// ConnectToManagementInterface establishes a connection to the given management
// interface and returns the accepted net.Conn and an error channel for the
// OpenVPN client.
func (s *Suite) ConnectToManagementInterface(ctx context.Context, tb testing.TB) {
	tb.Helper()

	s.errOpenVPNClientCh = make(chan error, 1)
	errTCPAcceptCh := make(chan error, 1)

	var err error

	go func(errCh chan<- error) {
		s.managementInterfaceConn, err = s.managementInterface.Accept()

		errCh <- err
	}(errTCPAcceptCh)

	go func(errCh chan<- error) {
		errCh <- s.openVPNClient.Connect(ctx)
	}(s.errOpenVPNClientCh)

	if err := <-errTCPAcceptCh; err != nil {
		require.NoError(tb, err, "error accepting connection to management interface: %s", s.Logs())
	}

	select {
	case err := <-s.errOpenVPNClientCh:
		require.NoError(tb, err, "error connecting OpenVPN client: %s", s.Logs())
	default:
	}

	require.NotNil(tb, s.managementInterfaceConn, "expected a connection to the management interface, but got nil. Logs: %s", s.Logs())

	s.managementInterfaceConnReader = bufio.NewReader(s.managementInterfaceConn)
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

	sendMessagef(tb, s.managementInterfaceConn, s.Logs, sendMessage, args...)
}

// ExpectMessage reads from the connection and compares the output with the
// expected message.
func (s *Suite) ExpectMessage(tb testing.TB, expectMessage string) {
	tb.Helper()

	expectConnMessage(tb, s.managementInterfaceConn, s.managementInterfaceConnReader, s.Logs, expectMessage)
}

// ExpectVersionAndReleaseHold performs the initial handshake with the mocked
// management interface. It checks for a version query and hold release.
func (s *Suite) ExpectVersionAndReleaseHold(tb testing.TB) {
	tb.Helper()

	expectVersionAndReleaseHold(tb, s.managementInterfaceConn, s.managementInterfaceConnReader, s.Logs)
}

// ReadLine reads a single line from the connection with a timeout.
func (s *Suite) ReadLine(tb testing.TB) string {
	tb.Helper()

	return readLine(tb, s.managementInterfaceConn, s.managementInterfaceConnReader)
}

func (s *Suite) Close(tb testing.TB) {
	tb.Helper()

	s.openVPNClient.Shutdown(tb.Context())

	select {
	case err := <-s.errOpenVPNClientCh:
		require.NoError(tb, err, "error shutting down OpenVPN client: %s", s.Logs())
	case <-time.After(3 * time.Second):
		tb.Fatalf("timeout waiting for connection to close. Logs:\n\n%s", s.Logs())
	}
}

func (s *Suite) GetHTTPClient() *http.Client {
	return s.httpClient
}

func (s *Suite) GetConfig() config.Config {
	return s.conf
}

func (s *Suite) GetOpenVPNClient() *openvpn.Client {
	return s.openVPNClient
}

func (s *Suite) GetManagementInterfaceConn() net.Conn {
	return s.managementInterfaceConn
}

func (s *Suite) GetManagementInterfaceConnReader() *bufio.Reader {
	return s.managementInterfaceConnReader
}

func (s *Suite) GetHTTPServerURL() string {
	return s.httpClientListener.URL
}

func (s *Suite) DoHTTPRequest(tb testing.TB, method, requestURL string, header http.Header, body io.Reader) (*http.Response, []byte, error) {
	tb.Helper()

	return DoHTTPRequest(tb, s.httpClient, s.httpClientListener.URL, method, requestURL, header, body)
}

func (s *Suite) setupManagementInterface(tb testing.TB) {
	tb.Helper()

	s.managementInterface = s.CreateTCPListener(tb)

	tb.Cleanup(func() {
		require.NoError(tb, s.managementInterface.Close())
	})

	s.conf.OpenVPN.Addr = types.URL{URL: &url.URL{Scheme: s.managementInterface.Addr().Network(), Host: s.managementInterface.Addr().String()}}
}

func (s *Suite) applyManagementDefaults() {
	if s.conf.HTTP.Secret == "" {
		s.conf.HTTP.Secret = Secret
	}

	if s.conf.OpenVPN.Bypass.CommonNames == nil {
		s.conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
	}
}

func (s *Suite) applyOIDCServerConfig(clientListener net.Listener, resourceServerURL types.URL, clientCredentials config.OAuth2Client) {
	s.conf.HTTP.BaseURL = types.URL{URL: &url.URL{Scheme: config.SchemeHTTP, Host: clientListener.Addr().String()}}

	if s.conf.HTTP.Secret == "" {
		s.conf.HTTP.Secret = Secret
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
}

func (s *Suite) connectOpenVPNManagement(ctx context.Context, tb testing.TB) <-chan error {
	tb.Helper()

	s.ConnectToManagementInterface(ctx, tb)

	return s.errOpenVPNClientCh
}
