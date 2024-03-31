package testutils

import (
	"bufio"
	"context"
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
	"unicode"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/generic"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/storage"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	oidcStorage "github.com/zitadel/oidc/v3/example/server/storage"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/net/nettest"
	"golang.org/x/text/language"
)

const Secret = "0123456789101112"

func ExpectVersionAndReleaseHold(tb testing.TB, conn net.Conn, reader *bufio.Reader) bool {
	tb.Helper()

	if !SendMessage(tb, conn, ">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info") {
		return false
	}

	if !SendMessage(tb, conn, ">HOLD:Waiting for hold release:0") {
		return false
	}

	var expectedCommand int

	for range 2 {
		line := ReadLine(tb, conn, reader)
		switch line {
		case "hold release":
			SendMessage(tb, conn, "SUCCESS: hold release succeeded")

			expectedCommand++
		case "version":
			SendMessage(tb, conn, "OpenVPN Version: OpenVPN Mock\r\nManagement Interface Version: 5\r\nEND")

			expectedCommand++
		default:
			assert.Contains(tb, []string{"version", "hold release"}, line)

			return false
		}
	}

	return assert.Equal(tb, 2, expectedCommand)
}

func SendMessage(tb testing.TB, conn net.Conn, sendMessage string, args ...any) bool {
	tb.Helper()

	if conn == nil {
		assert.Fail(tb, "connection is nil")

		return false
	}

	err := conn.SetWriteDeadline(time.Now().Add(time.Second * 5))
	if !assert.NoError(tb, err) { //nolint:testifylint
		return false
	}

	if sendMessage != "ENTER PASSWORD:" {
		sendMessage += "\r\n"
	}

	_, err = fmt.Fprintf(conn, sendMessage, args...)

	return assert.NoError(tb, err)
}

func ExpectMessage(tb testing.TB, conn net.Conn, reader *bufio.Reader, expectMessage string) bool {
	tb.Helper()

	var (
		err  error
		line string
	)

	for _, expected := range strings.Split(strings.TrimSpace(expectMessage), "\n") {
		err = conn.SetReadDeadline(time.Now().Add(time.Second * 5))
		if !assert.NoError(tb, err, expected, expectMessage) { //nolint:testifylint
			return false
		}

		line, err = reader.ReadString('\n')

		if err != nil && !errors.Is(err, io.EOF) {
			if !assert.NoError(tb, err, "expected line: %s\nexpected message:\n%s", expected, expectMessage) { //nolint:testifylint
				return false
			}
		}

		assert.Equal(tb, strings.TrimRightFunc(expected, unicode.IsSpace), strings.TrimRightFunc(line, unicode.IsSpace))
	}

	return true
}

func SendAndExpectMessage(tb testing.TB, conn net.Conn, reader *bufio.Reader, sendMessage string, expectMessage string) bool {
	tb.Helper()

	err := conn.SetWriteDeadline(time.Now().Add(time.Second * 5))
	if !assert.NoError(tb, err, "send: %s\n\nexpected message:\n%s", sendMessage, expectMessage) {
		return false
	}

	if sendMessage == "ENTER PASSWORD:" {
		_, err = fmt.Fprint(conn, sendMessage)
	} else {
		_, err = fmt.Fprintln(conn, sendMessage)
	}

	if !assert.NoError(tb, err, "send: %s\n\nexpected message:\n%s", sendMessage, expectMessage) {
		return false
	}

	var line string

	for _, expected := range strings.Split(strings.TrimSpace(expectMessage), "\n") {
		err = conn.SetReadDeadline(time.Now().Add(time.Second * 5))
		if !assert.NoError(tb, err, expected, expectMessage) { //nolint:testifylint
			return false
		}

		line, err = reader.ReadString('\n')

		//nolint:testifylint
		if err != nil && !errors.Is(err, io.EOF) && !assert.NoError(tb, err,
			"send: %s\n\nexpected line: %s\n\nexpected message:\n%s", sendMessage, expected, expectMessage) {
			return false
		}

		if !assert.Equal(tb, strings.TrimRightFunc(expected, unicode.IsSpace), strings.TrimRightFunc(line, unicode.IsSpace)) {
			return false
		}
	}

	return true
}

func ReadLine(tb testing.TB, conn net.Conn, reader *bufio.Reader) string {
	tb.Helper()

	err := conn.SetReadDeadline(time.Now().Add(time.Second * 5))
	require.NoError(tb, err)

	line, err := reader.ReadString('\n')

	if err != nil && !errors.Is(err, io.EOF) {
		require.NoError(tb, err)
	}

	return strings.TrimRightFunc(line, unicode.IsSpace)
}

func SetupResourceServer(tb testing.TB, clientListener net.Listener) (*httptest.Server, *url.URL, config.OAuth2Client, error) {
	tb.Helper()

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

	return resourceServer, resourceServerURL, config.OAuth2Client{ID: clientListener.Addr().String(), Secret: "SECRET"}, nil
}

// SetupMockEnvironment setups an OpenVPN and IDP mock
//
//nolint:cyclop
func SetupMockEnvironment(ctx context.Context, tb testing.TB, conf config.Config) (config.Config, *openvpn.Client, net.Listener, *oauth2.Provider,
	*httptest.Server, *http.Client, *Logger, func(),
) {
	tb.Helper()

	logger := NewTestLogger()

	managementInterface, err := nettest.NewLocalListener("tcp")
	require.NoError(tb, err)

	clientListener, err := nettest.NewLocalListener("tcp")
	require.NoError(tb, err)

	resourceServer, resourceServerURL, clientCredentials, err := SetupResourceServer(tb, clientListener)
	require.NoError(tb, err)

	if conf.HTTP.BaseURL == nil {
		conf.HTTP.BaseURL = &url.URL{Scheme: "http", Host: clientListener.Addr().String()}
	}

	if conf.HTTP.Secret == "" {
		conf.HTTP.Secret = Secret
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

	httpClient := &http.Client{Transport: NewMockRoundTripper(utils.NewUserAgentTransport(nil))}
	storageClient := storage.New(ctx, Secret, conf.OAuth2.Refresh.Expires)
	provider := oauth2.New(logger.Logger, conf, storageClient, httpClient)
	openvpnClient := openvpn.New(ctx, logger.Logger, conf, provider)

	require.NoError(tb, provider.Initialize(ctx, openvpnClient))

	httpClientListener := httptest.NewUnstartedServer(provider.Handler())
	httpClientListener.Listener.Close()
	httpClientListener.Listener = clientListener
	httpClientListener.Start()

	httpClientListenerClient := httpClientListener.Client()
	httpClientListenerClient.Transport = httpClient.Transport

	jar, err := cookiejar.New(nil)
	require.NoError(tb, err)

	httpClientListenerClient.Jar = jar

	return conf, openvpnClient, managementInterface, provider, httpClientListener, httpClientListenerClient, logger, func() {
		defer managementInterface.Close()
		defer clientListener.Close()
		defer resourceServer.Close()
		defer httpClientListener.Close()
	}
}
