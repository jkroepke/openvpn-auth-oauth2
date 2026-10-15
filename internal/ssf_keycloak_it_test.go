//go:build (darwin || linux || openbsd || freebsd) && cgo

package internal_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config/types"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/daemon"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/httphandler"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/revocation"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/ssf"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/test/testsuite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"golang.org/x/net/nettest"
)

const (
	// keycloakITImage needs SSF support, which is experimental and only in
	// Keycloak nightly builds yet. KEYCLOAK_IT_IMAGE overrides it.
	keycloakITImage = "quay.io/keycloak/keycloak:nightly"

	keycloakITAdmin        = "admin"
	keycloakITAdminSecret  = "admin"
	keycloakITClientID     = "openvpn-auth-oauth2"
	keycloakITClientSecret = "client-secret"
	keycloakITUser         = "alice"
	keycloakITUserPassword = "alice-password"
)

// keycloakIT is a Keycloak server with a realm that transmits SSF events to
// the openvpn-auth-oauth2 client over a poll stream.
type keycloakIT struct {
	client   *http.Client
	baseURL  string
	realm    string
	userID   string
	clientID string
}

// TestITSSFKeycloak runs the SSF receiver against Keycloak: a VPN client that
// logged in through Keycloak is terminated when an administrator deletes its
// session, and when an administrator signs the user out of all sessions.
//
// It starts Keycloak in a container. To use a running Keycloak with the
// "ssf" feature and the bootstrap admin admin/admin instead, set
// KEYCLOAK_IT_URL to its https base URL and KEYCLOAK_IT_CA_FILE to the CA of
// its certificate.
func TestITSSFKeycloak(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	if os.Getenv("CI") == "" && os.Getenv("OPENVPN_IT_TEST") != "1" {
		t.Skip("skipping integration test, OPENVPN_IT_TEST is not set")
	}

	keycloak := startKeycloakIT(t)

	clientListener, err := nettest.NewLocalListener("tcp")
	require.NoError(t, err)

	keycloak.setupRealm(t, fmt.Sprintf("http://%s/oauth2/callback", clientListener.Addr().String()))

	suite := startSSFKeycloakITService(t, keycloak, clientListener)

	// Deleting the Keycloak session of a client terminates it. The client
	// requests offline_access, so the ID token's sid names an offline session.
	authURL := connectSSFKeycloakITClient(t, suite, 1, "session-1")
	loginSSFKeycloakITClient(t, suite, keycloak, authURL, 1)

	sessions := keycloak.offlineSessions(t)
	require.Len(t, sessions, 1)

	keycloak.adminRequest(t, http.MethodDelete, "/sessions/"+sessions[0]+"?isOffline=true", nil, http.StatusNoContent)
	expectSSFKeycloakITKill(t, suite, 1)

	// Signing the user out of all sessions sends the session id "ALL", which
	// terminates every client of the user.
	authURL = connectSSFKeycloakITClient(t, suite, 2, "session-2")
	loginSSFKeycloakITClient(t, suite, keycloak, authURL, 2)

	keycloak.adminRequest(t, http.MethodPost, "/users/"+keycloak.userID+"/logout", nil, http.StatusNoContent)
	expectSSFKeycloakITKill(t, suite, 2)
}

func startSSFKeycloakITService(t *testing.T, keycloak *keycloakIT, clientListener net.Listener) *testsuite.Suite {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	issuer, err := types.NewURL(keycloak.baseURL + "/realms/" + keycloak.realm)
	require.NoError(t, err)

	conf := config.Defaults
	conf.HTTP.BaseURL = types.URL{URL: &url.URL{Scheme: config.SchemeHTTP, Host: clientListener.Addr().String()}}
	conf.OAuth2.Issuer = issuer
	conf.OAuth2.Client.ID = keycloakITClientID
	conf.OAuth2.Client.Secret = keycloakITClientSecret
	conf.OAuth2.Refresh.Enabled = true
	conf.OAuth2.Refresh.ValidateUser = true
	conf.OpenVPN.AuthTokenUser = false
	conf.SSF.Enabled = true
	conf.SSF.Poll.Interval = 200 * time.Millisecond

	suite := testsuite.New(&conf, testsuite.WithHTTPTransport(keycloak.client.Transport))
	errOpenVPNClientCh := suite.SetupManagementEnvironment(ctx, t, nil)
	suite.ExpectVersionAndReleaseHold(t)

	t.Cleanup(func() {
		require.NoError(t, suite.GetManagementInterfaceConn().Close())

		select {
		case err := <-errOpenVPNClientCh:
			require.NoError(t, err, suite.Logs())
		case <-time.After(5 * time.Second):
			t.Errorf("timeout waiting for the OpenVPN management client to stop. Logs:\n\n%s", suite.Logs())
		}
	})

	httpServer := httptest.NewUnstartedServer(httphandler.New(suite.GetConfig(), suite.GetOAuth2Client()))
	require.NoError(t, httpServer.Listener.Close())

	httpServer.Listener = clientListener
	httpServer.Start()
	t.Cleanup(httpServer.Close)

	enforcer := revocation.New(
		suite.GetLogger(), suite.GetConfig(), suite.GetSessionRegistry(), suite.GetOAuth2Client(), suite.GetOpenVPNClient(), nil,
	)

	receiver, err := daemon.NewSSFReceiver(ctx, suite.GetLogger(), suite.GetConfig(), suite.GetHTTPClient(), suite.GetOAuth2Client(), enforcer, nil)
	require.NoError(t, err, suite.Logs())

	done := make(chan error, 1)

	go func() { done <- receiver.Run(ctx) }()

	t.Cleanup(func() {
		cancel()
		require.NoError(t, <-done, suite.Logs())
	})

	return suite
}

// connectSSFKeycloakITClient sends a CLIENT:CONNECT and returns the pending auth URL.
func connectSSFKeycloakITClient(t *testing.T, suite *testsuite.Suite, cid uint64, sessionID string) string {
	t.Helper()

	suite.SendMessagef(t, ">CLIENT:CONNECT,%d,1\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,common_name=test\r\n"+
		">CLIENT:ENV,session_state=Initial\r\n>CLIENT:ENV,session_id=%s\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END",
		cid, sessionID)

	auth := suite.ReadLine(t)
	require.Contains(t, auth, fmt.Sprintf(`client-pending-auth %d 1 "WEB_AUTH::`, cid), suite.Logs())
	suite.SendMessagef(t, "SUCCESS: client-pending-auth command succeeded")

	return strings.TrimPrefix(strings.Split(auth, `"`)[1], "WEB_AUTH::")
}

var keycloakLoginFormAction = regexp.MustCompile(`<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"`)

// loginSSFKeycloakITClient logs in at the Keycloak login form of authURL and
// answers the client-auth command for cid.
func loginSSFKeycloakITClient(t *testing.T, suite *testsuite.Suite, keycloak *keycloakIT, authURL string, cid uint64) {
	t.Helper()

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	browser := &http.Client{Transport: keycloak.client.Transport, Jar: jar, Timeout: 30 * time.Second}

	status, body := httpRequest(t, browser, http.MethodGet, authURL, "", nil)
	require.Equal(t, http.StatusOK, status, string(body))

	action := keycloakLoginFormAction.FindSubmatch(body)
	require.NotNil(t, action, "Keycloak login form not found:\n%s", body)

	form := url.Values{"username": {keycloakITUser}, "password": {keycloakITUserPassword}, "credentialId": {""}}

	var (
		wg          sync.WaitGroup
		loginErr    error
		loginStatus int
	)

	wg.Go(func() {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, html.UnescapeString(string(action[1])), strings.NewReader(form.Encode()))
		if err != nil {
			loginErr = err

			return
		}

		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		loginResp, err := browser.Do(req)
		if err != nil {
			loginErr = err

			return
		}

		_, _ = io.Copy(io.Discard, loginResp.Body)
		_ = loginResp.Body.Close()
		loginStatus = loginResp.StatusCode
	})

	suite.ExpectMessage(t, fmt.Sprintf("client-auth-nt %d 1", cid))
	suite.SendMessagef(t, "SUCCESS: client-auth command succeeded")

	wg.Wait()
	require.NoError(t, loginErr)
	require.Equal(t, http.StatusOK, loginStatus, suite.Logs())
}

// expectSSFKeycloakITKill waits until the revocation of cid started, which
// removes it from the session registry first, and answers its client-kill.
func expectSSFKeycloakITKill(t *testing.T, suite *testsuite.Suite, cid uint64) {
	t.Helper()

	// Keycloak queues events, so the revocation can take a few polls.
	if !assert.EventuallyWithT(t, func(collect *assert.CollectT) {
		assert.Equal(collect, 0, suite.GetSessionRegistry().Len())
	}, 30*time.Second, 50*time.Millisecond) {
		t.Fatalf("client %d was not revoked. Logs:\n\n%s", cid, suite.Logs())
	}

	suite.ExpectMessage(t, fmt.Sprintf("client-kill %d HALT", cid))
	suite.SendMessagef(t, "SUCCESS: client-kill command succeeded")
}

func startKeycloakIT(t *testing.T) *keycloakIT {
	t.Helper()

	if baseURL := os.Getenv("KEYCLOAK_IT_URL"); baseURL != "" {
		caPEM, err := os.ReadFile(os.Getenv("KEYCLOAK_IT_CA_FILE"))
		require.NoError(t, err, "KEYCLOAK_IT_CA_FILE")

		return newKeycloakIT(t, strings.TrimSuffix(baseURL, "/"), caPEM)
	}

	testcontainers.SkipIfProviderIsNotHealthy(t)

	certPEM, keyPEM := keycloakITCertificate(t)

	image := os.Getenv("KEYCLOAK_IT_IMAGE")
	if image == "" {
		image = keycloakITImage
	}

	container, err := testcontainers.Run(
		t.Context(),
		image,
		testcontainers.WithExposedPorts("8443/tcp"),
		testcontainers.WithLabels(map[string]string{"testcontainers": "true"}),
		testcontainers.WithEnv(map[string]string{
			"KC_BOOTSTRAP_ADMIN_USERNAME": keycloakITAdmin,
			"KC_BOOTSTRAP_ADMIN_PASSWORD": keycloakITAdminSecret,
		}),
		testcontainers.WithFiles(
			testcontainers.ContainerFile{Reader: bytes.NewReader(certPEM), ContainerFilePath: "/opt/keycloak/conf/it.crt", FileMode: 0o644},
			testcontainers.ContainerFile{Reader: bytes.NewReader(keyPEM), ContainerFilePath: "/opt/keycloak/conf/it.key", FileMode: 0o644},
		),
		testcontainers.WithCmd(
			"start-dev",
			"--features=ssf",
			"--https-certificate-file=/opt/keycloak/conf/it.crt",
			"--https-certificate-key-file=/opt/keycloak/conf/it.key",
		),
		testcontainers.WithWaitStrategy(wait.ForLog("Listening on:").WithStartupTimeout(5*time.Minute)),
	)
	if container != nil {
		testcontainers.CleanupContainer(t, container)
	}

	require.NoError(t, err, openVPNITContainerLogs(t, container))

	endpoint, err := container.PortEndpoint(t.Context(), "8443/tcp", "https")
	require.NoError(t, err)

	return newKeycloakIT(t, endpoint, certPEM)
}

func newKeycloakIT(t *testing.T, baseURL string, caPEM []byte) *keycloakIT {
	t.Helper()

	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(caPEM), "no certificate in the Keycloak CA")

	transport := http.DefaultTransport.(*http.Transport).Clone() //nolint:forcetypeassert // the default transport
	transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}

	return &keycloakIT{
		client:  &http.Client{Transport: transport, Timeout: 30 * time.Second},
		baseURL: baseURL,
		realm:   fmt.Sprintf("ssf-it-%d", time.Now().UnixNano()),
	}
}

// keycloakITCertificate returns a self-signed certificate for localhost and its key.
func keycloakITCertificate(t *testing.T) ([]byte, []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

// setupRealm creates a realm with the SSF transmitter enabled, a user, and a
// confidential client with SSF poll delivery and one stream, the way the
// "Shared Signals" documentation describes it.
func (k *keycloakIT) setupRealm(t *testing.T, redirectURI string) {
	t.Helper()

	k.request(t, http.MethodPost, "/admin/realms", k.adminToken(t), map[string]any{
		"realm":      k.realm,
		"enabled":    true,
		"attributes": map[string]string{"ssf.transmitterEnabled": "true"},
	}, http.StatusCreated)

	// A Keycloak from KEYCLOAK_IT_URL outlives the test.
	t.Cleanup(func() { k.deleteRealm(t) })

	k.adminRequest(t, http.MethodPost, "/users", map[string]any{
		"username":      keycloakITUser,
		"enabled":       true,
		"email":         keycloakITUser + "@example.com",
		"emailVerified": true,
		"firstName":     "Alice",
		"lastName":      "Example",
		"credentials":   []map[string]any{{"type": "password", "value": keycloakITUserPassword, "temporary": false}},
	}, http.StatusCreated)

	var users []struct {
		ID string `json:"id"`
	}

	require.NoError(t, json.Unmarshal(k.adminRequest(t, http.MethodGet, "/users?exact=true&username="+keycloakITUser, nil, http.StatusOK), &users))
	require.Len(t, users, 1)

	k.userID = users[0].ID

	k.adminRequest(t, http.MethodPost, "/clients", map[string]any{
		"clientId":               keycloakITClientID,
		"secret":                 keycloakITClientSecret,
		"publicClient":           false,
		"standardFlowEnabled":    true,
		"serviceAccountsEnabled": true,
		"redirectUris":           []string{redirectURI},
		"attributes": map[string]string{
			"ssf.enabled":                "true",
			"ssf.allowedDeliveryMethods": "poll",
			"ssf.defaultSubjects":        "ALL",
		},
	}, http.StatusCreated)

	var clients []struct {
		ID string `json:"id"`
	}

	require.NoError(t, json.Unmarshal(k.adminRequest(t, http.MethodGet, "/clients?clientId="+keycloakITClientID, nil, http.StatusOK), &clients))
	require.Len(t, clients, 1)

	k.clientID = clients[0].ID

	var scopes []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}

	require.NoError(t, json.Unmarshal(k.adminRequest(t, http.MethodGet, "/client-scopes", nil, http.StatusOK), &scopes))

	assigned := 0

	for _, scope := range scopes {
		if scope.Name == "ssf.read" || scope.Name == "ssf.manage" {
			k.adminRequest(t, http.MethodPut, "/clients/"+k.clientID+"/optional-client-scopes/"+scope.ID, nil, http.StatusNoContent)

			assigned++
		}
	}

	require.Equal(t, 2, assigned, "client scopes ssf.read and ssf.manage not found")

	// The receiver doesn't create streams, so create it like an administrator would.
	k.request(t, http.MethodPost, "/realms/"+k.realm+"/ssf/transmitter/streams", k.clientToken(t, "ssf.manage"), map[string]any{
		"delivery":         map[string]string{"method": ssf.DeliveryMethodPoll},
		"events_requested": []string{ssf.EventTypeSessionRevoked},
	}, http.StatusCreated)
}

// offlineSessions returns the ids of the offline sessions of the user with
// the openvpn-auth-oauth2 client.
func (k *keycloakIT) offlineSessions(t *testing.T) []string {
	t.Helper()

	var sessions []struct {
		ID string `json:"id"`
	}

	require.NoError(t, json.Unmarshal(k.adminRequest(t, http.MethodGet, "/users/"+k.userID+"/offline-sessions/"+k.clientID, nil, http.StatusOK), &sessions))

	ids := make([]string, 0, len(sessions))
	for _, session := range sessions {
		ids = append(ids, session.ID)
	}

	return ids
}

// deleteRealm deletes the realm of the test. It runs after the test context
// is canceled, so it uses its own context and only logs errors.
func (k *keycloakIT) deleteRealm(t *testing.T) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 30*time.Second)
	defer cancel()

	form := url.Values{
		"grant_type": {"password"},
		"client_id":  {"admin-cli"},
		"username":   {keycloakITAdmin},
		"password":   {keycloakITAdminSecret},
	}

	send := func(method, path, token string, body io.Reader) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, method, k.baseURL+path, body)
		if err != nil {
			return nil, err
		}

		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		} else {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}

		resp, err := k.client.Do(req)
		if err != nil {
			return nil, err
		}

		defer func() { _ = resp.Body.Close() }()

		data, err := io.ReadAll(resp.Body)
		if err == nil && resp.StatusCode >= http.StatusMultipleChoices {
			err = fmt.Errorf("%s %s: status %d: %s", method, path, resp.StatusCode, data)
		}

		return data, err
	}

	data, err := send(http.MethodPost, "/realms/master/protocol/openid-connect/token", "", strings.NewReader(form.Encode()))
	if err != nil {
		t.Logf("delete realm %s: %v", k.realm, err)

		return
	}

	var token struct {
		AccessToken string `json:"access_token"` //nolint:tagliatelle // OAuth 2.0 member name
	}

	if err = json.Unmarshal(data, &token); err != nil {
		t.Logf("delete realm %s: %v", k.realm, err)

		return
	}

	if _, err = send(http.MethodDelete, "/admin/realms/"+k.realm, token.AccessToken, http.NoBody); err != nil {
		t.Logf("delete realm %s: %v", k.realm, err)
	}
}

func (k *keycloakIT) adminToken(t *testing.T) string {
	t.Helper()

	return k.token(t, "/realms/master/protocol/openid-connect/token", url.Values{
		"grant_type": {"password"},
		"client_id":  {"admin-cli"},
		"username":   {keycloakITAdmin},
		"password":   {keycloakITAdminSecret},
	})
}

func (k *keycloakIT) clientToken(t *testing.T, scope string) string {
	t.Helper()

	return k.token(t, "/realms/"+k.realm+"/protocol/openid-connect/token", url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {keycloakITClientID},
		"client_secret": {keycloakITClientSecret},
		"scope":         {scope},
	})
}

func (k *keycloakIT) token(t *testing.T, path string, form url.Values) string {
	t.Helper()

	status, body := httpRequest(t, k.client, http.MethodPost, k.baseURL+path, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	require.Equal(t, http.StatusOK, status, string(body))

	var token struct {
		AccessToken string `json:"access_token"` //nolint:tagliatelle // OAuth 2.0 member name
	}

	require.NoError(t, json.Unmarshal(body, &token))

	return token.AccessToken
}

func (k *keycloakIT) adminRequest(t *testing.T, method, path string, payload any, status int) []byte {
	t.Helper()

	return k.request(t, method, "/admin/realms/"+k.realm+path, k.adminToken(t), payload, status)
}

func (k *keycloakIT) request(t *testing.T, method, path, token string, payload any, status int) []byte {
	t.Helper()

	var (
		body        io.Reader
		contentType string
	)

	if payload != nil {
		data, err := json.Marshal(payload)
		require.NoError(t, err)

		body, contentType = bytes.NewReader(data), "application/json"
	}

	req, err := http.NewRequestWithContext(t.Context(), method, k.baseURL+path, body)
	require.NoError(t, err)

	req.Header.Set("Authorization", "Bearer "+token)

	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	resp, err := k.client.Do(req)
	require.NoError(t, err)

	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, status, resp.StatusCode, "%s %s: %s", method, path, data)

	return data
}

func httpRequest(t *testing.T, client *http.Client, method, location, contentType string, body io.Reader) (int, []byte) {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), method, location, body)
	require.NoError(t, err)

	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	resp, err := client.Do(req)
	require.NoError(t, err)

	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	return resp.StatusCode, data
}
