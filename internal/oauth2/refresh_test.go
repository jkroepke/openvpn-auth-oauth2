package oauth2_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	configtypes "github.com/jkroepke/openvpn-auth-oauth2/internal/config/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/generic"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/github"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/google"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/test/testsuite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

func configTypesFS(files map[string][]byte) configtypes.FS {
	mapFS := make(fstest.MapFS, len(files))
	for name, data := range files {
		mapFS[name] = &fstest.MapFile{Data: data}
	}

	return configtypes.FS{FS: mapFS}
}

func expectProfileClientAuth(t *testing.T, suite *testsuite.Suite, cid, kid uint64) {
	t.Helper()

	suite.ExpectMessage(t, fmt.Sprintf("client-auth %d %d", cid, kid))
	suite.ExpectMessage(t, `push "route 10.8.0.0 255.255.0.0"`)
	suite.ExpectMessage(t, "END")
}

func TestRefreshReAuth(t *testing.T) {
	t.Parallel()

	var refreshToken string

	for _, tc := range []struct {
		name                     string
		clientCommonName         string
		nonInteractiveShouldWork bool
		conf                     config.Config
		rt                       http.RoundTripper
		opConf                   *op.Config
	}{
		{
			name:                     "Refresh",
			clientCommonName:         "test",
			nonInteractiveShouldWork: true,
			conf: func() config.Config {
				conf := config.Defaults
				conf.OAuth2.OpenVPNUsername = "oauth2TokenClaims." + testsuite.SubjectClaim
				conf.OAuth2.Refresh.Enabled = true
				conf.OAuth2.Refresh.ValidateUser = true
				conf.OAuth2.Refresh.UseSessionID = false

				return conf
			}(),
			rt: http.DefaultTransport,
		},
		{
			name:                     "ReAuthentication disabled",
			clientCommonName:         "test",
			nonInteractiveShouldWork: true,
			conf: func() config.Config {
				conf := config.Defaults
				conf.OAuth2.OpenVPNUsername = "oauth2TokenClaims." + testsuite.SubjectClaim
				conf.OpenVPN.ReAuthentication = false

				return conf
			}(),
			rt: http.DefaultTransport,
		},
		{
			name:                     "Refresh with empty common name",
			clientCommonName:         "",
			nonInteractiveShouldWork: true,
			conf: func() config.Config {
				conf := config.Defaults
				conf.OAuth2.OpenVPNUsername = ""
				conf.OpenVPN.AuthTokenUser = true
				conf.OAuth2.Refresh.Enabled = true
				conf.OAuth2.Refresh.ValidateUser = true
				conf.OAuth2.Refresh.UseSessionID = false

				return conf
			}(),
			rt: http.DefaultTransport,
		},
		{
			name:                     "Refresh with OverrideUsername=true",
			clientCommonName:         "test",
			nonInteractiveShouldWork: true,
			conf: func() config.Config {
				conf := config.Defaults
				conf.OAuth2.OpenVPNUsername = "oauth2TokenClaims." + testsuite.SubjectClaim
				conf.OpenVPN.AuthTokenUser = true
				conf.OpenVPN.OverrideUsername = true
				conf.OAuth2.Refresh.Enabled = true
				conf.OAuth2.Refresh.ValidateUser = true
				conf.OAuth2.Refresh.UseSessionID = false

				return conf
			}(),
			rt: http.DefaultTransport,
		},
		{
			name:                     "Refresh with ValidateUser=false",
			clientCommonName:         "test",
			nonInteractiveShouldWork: true,
			conf: func() config.Config {
				conf := config.Defaults
				conf.OAuth2.OpenVPNUsername = "oauth2TokenClaims." + testsuite.SubjectClaim
				conf.OAuth2.Refresh.Enabled = true
				conf.OAuth2.Refresh.ValidateUser = false
				conf.OAuth2.Refresh.UseSessionID = false

				return conf
			}(),
			rt: http.DefaultTransport,
		},
		{
			name:                     "Refresh with ValidateUser=false and client config",
			clientCommonName:         "test",
			nonInteractiveShouldWork: true,
			conf: func() config.Config {
				conf := config.Defaults
				conf.OAuth2.OpenVPNUsername = "oauth2TokenClaims." + testsuite.SubjectClaim
				conf.OAuth2.Refresh.Enabled = true
				conf.OAuth2.Refresh.ValidateUser = false
				conf.OAuth2.Refresh.UseSessionID = false
				conf.OpenVPN.ClientConfig.Enabled = true
				conf.OpenVPN.ClientConfig.Expression = `["profile"]`
				conf.OpenVPN.ClientConfig.Path = configTypesFS(map[string][]byte{
					"profile.conf": []byte(`push "route 10.8.0.0 255.255.0.0"`),
				})

				return conf
			}(),
			rt: http.DefaultTransport,
		},
		{
			name:                     "Refresh with UserInfo=true",
			clientCommonName:         "test",
			nonInteractiveShouldWork: true,
			conf: func() config.Config {
				conf := config.Defaults
				conf.OAuth2.OpenVPNUsername = "oauth2TokenClaims." + testsuite.SubjectClaim
				conf.OAuth2.Validate.Groups = []string{"group1"}
				conf.OAuth2.UserInfo = true
				conf.OAuth2.Refresh.Enabled = true

				return conf
			}(),
			rt: http.DefaultTransport,
		},
		{
			name:                     "Refresh with SessionID=true + ValidateUser=false",
			clientCommonName:         "test",
			nonInteractiveShouldWork: true,
			conf: func() config.Config {
				conf := config.Defaults
				conf.OAuth2.OpenVPNUsername = "oauth2TokenClaims." + testsuite.SubjectClaim
				conf.OpenVPN.AuthTokenUser = false
				conf.OAuth2.Refresh.Enabled = true
				conf.OAuth2.Refresh.ValidateUser = false
				conf.OAuth2.Refresh.UseSessionID = true

				return conf
			}(),
			rt: http.DefaultTransport,
		},
		{
			name:                     "Refresh with SessionID=true + ValidateUser=true",
			clientCommonName:         "test",
			nonInteractiveShouldWork: true,
			conf: func() config.Config {
				conf := config.Defaults
				conf.OAuth2.OpenVPNUsername = "oauth2TokenClaims." + testsuite.SubjectClaim
				conf.OpenVPN.AuthTokenUser = false
				conf.OAuth2.Refresh.Enabled = true
				conf.OAuth2.Refresh.ValidateUser = true
				conf.OAuth2.Refresh.UseSessionID = true

				return conf
			}(),
			rt: http.DefaultTransport,
		},
		{
			name:                     "Refresh with provider=google",
			clientCommonName:         "test",
			nonInteractiveShouldWork: true,
			conf: func() config.Config {
				conf := config.Defaults
				conf.OAuth2.OpenVPNUsername = "oauth2TokenClaims." + testsuite.SubjectClaim
				conf.OpenVPN.AuthTokenUser = false
				conf.OAuth2.Provider = google.Name
				conf.OAuth2.Scopes = []string{types.ScopeEmail, types.ScopeProfile, types.ScopeOpenID, types.ScopeOfflineAccess}
				conf.OAuth2.Refresh.Enabled = true
				conf.OAuth2.Refresh.ValidateUser = true
				conf.OAuth2.Refresh.UseSessionID = false

				return conf
			}(),
			rt: http.DefaultTransport,
		},
		{
			name:                     "Refresh with provider=github",
			clientCommonName:         "test",
			nonInteractiveShouldWork: true,
			conf: func() config.Config {
				conf := config.Defaults
				conf.OAuth2.OpenVPNUsername = "oauth2TokenClaims." + testsuite.SubjectClaim
				conf.OpenVPN.AuthTokenUser = false
				conf.OAuth2.Provider = github.Name
				conf.OAuth2.Refresh.Enabled = true
				conf.OAuth2.Refresh.ValidateUser = true
				conf.OAuth2.Refresh.UseSessionID = false

				return conf
			}(),
			rt: http.DefaultTransport,
		},
		{
			name:                     "Refresh without server support",
			clientCommonName:         "test",
			nonInteractiveShouldWork: false,
			conf: func() config.Config {
				conf := config.Defaults
				conf.OAuth2.OpenVPNUsername = "oauth2TokenClaims." + testsuite.SubjectClaim
				conf.OAuth2.Refresh.Enabled = true
				conf.OAuth2.Refresh.ValidateUser = true
				conf.OAuth2.Refresh.UseSessionID = false

				return conf
			}(),
			rt: http.DefaultTransport,
			opConf: &op.Config{
				CryptoKey:                testsuite.HashSecret,
				DefaultLogoutRedirectURI: "/",
				CodeMethodS256:           true,
				AuthMethodPost:           true,
				AuthMethodPrivateKeyJWT:  true,
				GrantTypeRefreshToken:    false,
				RequestObjectSupported:   true,
				SupportedUILocales:       testsuite.SupportedUILocales,
				SupportedScopes:          []string{types.ScopeOpenID, types.ScopeProfile, types.ScopeOfflineAccess},
			},
		},
		{
			name:                     "Refresh with failed non-interactive authentication",
			clientCommonName:         "test",
			nonInteractiveShouldWork: false,
			conf: func() config.Config {
				conf := config.Defaults
				conf.OAuth2.OpenVPNUsername = "oauth2TokenClaims." + testsuite.SubjectClaim
				conf.OpenVPN.AuthTokenUser = false
				conf.OAuth2.Provider = generic.Name
				conf.OAuth2.Refresh.Enabled = true
				conf.OAuth2.Refresh.ValidateUser = true
				conf.OAuth2.Refresh.UseSessionID = false

				return conf
			}(),
			rt: testsuite.NewRoundTripperFunc(http.DefaultTransport, func(rt http.RoundTripper, req *http.Request) (*http.Response, error) {
				if req.URL.Path != "/oauth/token" {
					return rt.RoundTrip(req)
				}

				requestBody, err := io.ReadAll(req.Body)
				if err != nil {
					return nil, err
				}

				// Initial request should work
				if strings.Contains(string(requestBody), `&code=`) {
					req.Body = io.NopCloser(bytes.NewReader(requestBody))

					return rt.RoundTrip(req)
				}

				res := httptest.NewRecorder()
				res.WriteHeader(http.StatusInternalServerError)

				return res.Result(), nil
			}),
		},
		{
			name:                     "Refresh without returning refresh token",
			clientCommonName:         "test",
			nonInteractiveShouldWork: true,
			conf: func() config.Config {
				conf := config.Defaults
				conf.OAuth2.OpenVPNUsername = "oauth2TokenClaims." + testsuite.SubjectClaim
				conf.OpenVPN.AuthTokenUser = false
				conf.OAuth2.Provider = generic.Name
				conf.OAuth2.Refresh.Enabled = true
				conf.OAuth2.Refresh.ValidateUser = true
				conf.OAuth2.Refresh.UseSessionID = false

				return conf
			}(),
			rt: testsuite.NewRoundTripperFunc(http.DefaultTransport, func(rt http.RoundTripper, req *http.Request) (*http.Response, error) {
				if req.URL.Path != "/oauth/token" {
					return rt.RoundTrip(req)
				}

				requestBody, err := io.ReadAll(req.Body)
				if err != nil {
					return nil, err
				}

				if refreshToken == "" {
					req.Body = io.NopCloser(bytes.NewReader(requestBody))
					res, err := rt.RoundTrip(req)

					var tokenResponse oidc.AccessTokenResponse
					if err := json.NewDecoder(res.Body).Decode(&tokenResponse); err != nil {
						return nil, err
					}

					refreshToken = tokenResponse.RefreshToken

					var buf bytes.Buffer

					if err := json.NewEncoder(&buf).Encode(tokenResponse); err != nil {
						return nil, err
					}

					res.Body = io.NopCloser(&buf)

					return res, err
				}

				res := httptest.NewRecorder()
				if !strings.Contains(string(requestBody), refreshToken) {
					res.WriteHeader(http.StatusUnauthorized)
				} else {
					res.WriteHeader(http.StatusOK)
				}

				if _, err := res.WriteString(`{}`); err != nil {
					return nil, err
				}

				return res.Result(), nil
			}),
		},
		{
			name:                     "refresh with CEL denying non-interactive auth",
			clientCommonName:         "test",
			nonInteractiveShouldWork: false,
			conf: func() config.Config {
				conf := config.Defaults
				conf.OAuth2.OpenVPNUsername = "oauth2TokenClaims." + testsuite.SubjectClaim
				conf.OpenVPN.AuthTokenUser = false
				conf.OAuth2.Provider = generic.Name
				conf.OAuth2.Refresh.Enabled = true
				conf.OAuth2.Refresh.ValidateUser = true
				conf.OAuth2.Refresh.UseSessionID = false
				conf.OAuth2.Validate.Expression = "authMode == 'interactive'"

				return conf
			}(),
			rt: http.DefaultTransport,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(cancel)

			suite := testsuite.New(&tc.conf, testsuite.WithHTTPTransport(tc.rt))
			errOpenVPNClientCh := suite.SetupMockEnvironment(ctx, t, tc.opConf)
			conf := suite.GetConfig()
			httpClient := suite.GetHTTPClient()
			suite.ExpectVersionAndReleaseHold(t)

			suite.SendMessagef(
				t,
				">CLIENT:CONNECT,1,2\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,common_name=%s\r\n>CLIENT:ENV,session_state=Initial\r\n>CLIENT:ENV,session_id=session_id\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END",
				tc.clientCommonName,
			)

			auth := suite.ReadLine(t)
			assert.Contains(t, auth, "client-pending-auth 1 2 \"WEB_AUTH::")
			suite.SendMessagef(t, "SUCCESS: %s command succeeded", strings.SplitN(auth, " ", 2)[0])

			authURL := strings.TrimPrefix(strings.Split(auth, `"`)[1], "WEB_AUTH::")

			var (
				resp   *http.Response
				reqErr error
			)

			wg := sync.WaitGroup{}
			wg.Go(func() {
				resp, _, reqErr = testsuite.DoHTTPRequest(t, httpClient, "", http.MethodGet, authURL, nil, http.NoBody) //nolint:bodyclose
			})

			t.Cleanup(func() {
				require.NoError(t, suite.GetManagementInterfaceConn().Close())

				select {
				case err := <-errOpenVPNClientCh:
					require.NoError(t, err, suite.Logs())
				case <-time.After(1 * time.Second):
					t.Fatalf("timeout waiting for connection to close. Logs:\n\n%s", suite.Logs())
				}
			})

			switch {
			case !tc.conf.OAuth2.Refresh.ValidateUser && tc.conf.OpenVPN.ClientConfig.Enabled:
				expectProfileClientAuth(t, suite, 1, 2)
			case !tc.conf.OAuth2.Refresh.ValidateUser:
				suite.ExpectMessage(t, "client-auth-nt 1 2")
			case tc.conf.OpenVPN.OverrideUsername:
				suite.ExpectMessage(t, "client-auth 1 2")

				switch {
				case tc.clientCommonName == "":
					suite.ExpectMessage(t, `override-username "username"`)
				case tc.conf.OAuth2.UserInfo:
					suite.ExpectMessage(t, `override-username "test-user@localhost"`)
				default:
					suite.ExpectMessage(t, `override-username "id1"`)
				}

				suite.ExpectMessage(t, "END")
			case tc.conf.OpenVPN.AuthTokenUser:
				suite.ExpectMessage(t, "client-auth 1 2")

				switch {
				case tc.clientCommonName == "":
					suite.ExpectMessage(t, `push "auth-token-user dXNlcm5hbWU="`)
				case tc.conf.OAuth2.UserInfo:
					suite.ExpectMessage(t, `push "auth-token-user dGVzdC11c2VyQGxvY2FsaG9zdA=="`)
				default:
					suite.ExpectMessage(t, `push "auth-token-user aWQx"`)
				}

				suite.ExpectMessage(t, "END")
			default:
				suite.ExpectMessage(t, "client-auth-nt 1 2")
			}

			suite.SendMessagef(t, "SUCCESS: client-auth command succeeded")

			wg.Wait()

			require.NoError(t, reqErr)
			require.Equal(t, http.StatusOK, resp.StatusCode)

			// Testing ReAuth
			suite.SendMessagef(
				t,
				">CLIENT:ESTABLISHED,0\r\n>CLIENT:ENV,common_name=bypass\r\n>CLIENT:ENV,END\r\n",
			)

			// Testing ReAuth
			suite.SendMessagef(
				t,
				">CLIENT:REAUTH,1,3\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,common_name=%s\r\n>CLIENT:ENV,session_id=session_id\r\n>CLIENT:ENV,session_state=AuthenticatedEmptyUser\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END",
				tc.clientCommonName,
			)

			if !tc.conf.OpenVPN.ReAuthentication {
				suite.ExpectMessage(t, "client-deny 1 3 \"client re-authentication not enabled\"")
				suite.SendMessagef(t, "SUCCESS: client-deny command succeeded")

				return
			}

			if !tc.nonInteractiveShouldWork {
				auth := suite.ReadLine(t)
				assert.Contains(t, auth, "client-pending-auth 1 3 \"WEB_AUTH::")
				suite.SendMessagef(t, "SUCCESS: %s command succeeded", strings.SplitN(auth, " ", 2)[0])

				return
			}

			switch {
			case !tc.conf.OAuth2.Refresh.ValidateUser && tc.conf.OpenVPN.ClientConfig.Enabled:
				expectProfileClientAuth(t, suite, 1, 3)
			case !tc.conf.OAuth2.Refresh.ValidateUser:
				suite.ExpectMessage(t, "client-auth-nt 1 3")
			case tc.conf.OpenVPN.OverrideUsername:
				suite.ExpectMessage(t, "client-auth 1 3")

				switch {
				case tc.clientCommonName == "":
					suite.ExpectMessage(t, `override-username "username"`)
				case tc.conf.OAuth2.UserInfo:
					suite.ExpectMessage(t, `override-username "test-user@localhost"`)
				default:
					suite.ExpectMessage(t, `override-username "id1"`)
				}

				suite.ExpectMessage(t, "END")
			case tc.conf.OpenVPN.AuthTokenUser:
				suite.ExpectMessage(t, "client-auth 1 3")

				switch {
				case tc.clientCommonName == "":
					suite.ExpectMessage(t, `push "auth-token-user dXNlcm5hbWU="`)
				case tc.conf.OAuth2.UserInfo:
					suite.ExpectMessage(t, `push "auth-token-user dGVzdC11c2VyQGxvY2FsaG9zdA=="`)
				default:
					suite.ExpectMessage(t, `push "auth-token-user aWQx"`)
				}

				suite.ExpectMessage(t, "END")
			default:
				suite.ExpectMessage(t, "client-auth-nt 1 3")
			}

			suite.SendMessagef(t, "SUCCESS: client-auth command succeeded")

			// Testing ReAuth
			suite.SendMessagef(
				t,
				">CLIENT:REAUTH,1,4\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,common_name=%s\r\n>CLIENT:ENV,session_id=session_id\r\n>CLIENT:ENV,session_state=AuthenticatedEmptyUser\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END",
				tc.clientCommonName,
			)

			switch {
			case !tc.conf.OAuth2.Refresh.ValidateUser && tc.conf.OpenVPN.ClientConfig.Enabled:
				expectProfileClientAuth(t, suite, 1, 4)
			case !tc.conf.OAuth2.Refresh.ValidateUser:
				suite.ExpectMessage(t, "client-auth-nt 1 4")
			case tc.conf.OpenVPN.OverrideUsername:
				suite.ExpectMessage(t, "client-auth 1 4")

				switch {
				case tc.clientCommonName == "":
					suite.ExpectMessage(t, `override-username "username"`)
				case tc.conf.OAuth2.UserInfo:
					suite.ExpectMessage(t, `override-username "test-user@localhost"`)
				default:
					suite.ExpectMessage(t, `override-username "id1"`)
				}

				suite.ExpectMessage(t, "END")
			case tc.conf.OpenVPN.AuthTokenUser:
				suite.ExpectMessage(t, "client-auth 1 4")

				switch {
				case tc.clientCommonName == "":
					suite.ExpectMessage(t, `push "auth-token-user dXNlcm5hbWU="`)
				case tc.conf.OAuth2.UserInfo:
					suite.ExpectMessage(t, `push "auth-token-user dGVzdC11c2VyQGxvY2FsaG9zdA=="`)
				default:
					suite.ExpectMessage(t, `push "auth-token-user aWQx"`)
				}

				suite.ExpectMessage(t, "END")
			default:
				suite.ExpectMessage(t, "client-auth-nt 1 4")
			}

			suite.SendMessagef(t, "SUCCESS: client-auth command succeeded")

			// Test Disconnect
			suite.SendMessagef(t, ">CLIENT:DISCONNECT,1\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,common_name=test\r\n>CLIENT:ENV,session_id=session_id\r\n>CLIENT:ENV,session_state=AuthenticatedEmptyUser\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END")

			// Test ReAuth after DC
			suite.SendMessagef(t, ">CLIENT:REAUTH,1,4\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,common_name=test\r\n>CLIENT:ENV,session_id=session_id\r\n>CLIENT:ENV,session_state=AuthenticatedEmptyUser\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END")

			switch {
			case conf.OAuth2.Refresh.UseSessionID:
				if !tc.conf.OAuth2.Refresh.ValidateUser || !tc.conf.OpenVPN.AuthTokenUser {
					suite.ExpectMessage(t, "client-auth-nt 1 4")
				} else {
					suite.ExpectMessage(t, "client-auth 1 4")

					switch {
					case tc.clientCommonName == "":
						suite.ExpectMessage(t, `push "auth-token-user dXNlcm5hbWU="`)
					case tc.conf.OAuth2.UserInfo:
						suite.ExpectMessage(t, `push "auth-token-user dGVzdC11c2VyQGxvY2FsaG9zdA=="`)
					default:
						suite.ExpectMessage(t, `push "auth-token-user aWQx"`)
					}
				}
			default:
				auth = suite.ReadLine(t)
				require.Contains(t, auth, "client-pending-auth 1 4 \"WEB_AUTH::")
			}

			suite.SendMessagef(t, "SUCCESS: %s command succeeded", strings.SplitN(auth, " ", 2)[0])

			// Test ReAuth after DC with different CID
			suite.SendMessagef(t, ">CLIENT:CONNECT,2,3\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,common_name=test\r\n>CLIENT:ENV,session_id=session_id\r\n>CLIENT:ENV,session_state=AuthenticatedEmptyUser\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END")

			auth = suite.ReadLine(t)

			if conf.OAuth2.Refresh.UseSessionID {
				require.Contains(t, auth, "client-auth-nt 2 3")
			} else {
				require.Contains(t, auth, "client-pending-auth 2 3 \"WEB_AUTH::")
			}

			suite.SendMessagef(t, "SUCCESS: %s command succeeded", strings.SplitN(auth, " ", 2)[0])

			// Test ReAuth after DC with different CID with invalid session
			suite.SendMessagef(t, ">CLIENT:CONNECT,3,3\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,common_name=test\r\n>CLIENT:ENV,session_id=session_id\r\n>CLIENT:ENV,session_state=Expired\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END")

			auth = suite.ReadLine(t)

			if conf.OAuth2.Refresh.UseSessionID {
				assert.Equal(t, fmt.Sprintf(`client-deny 3 3 "%s"`, openvpn.ReasonStateExpiredOrInvalid), auth)
			} else {
				assert.Contains(t, auth, `client-pending-auth 3 3 "WEB_AUTH::`)
			}

			suite.SendMessagef(t, "SUCCESS: %s command succeeded", strings.SplitN(auth, " ", 2)[0])
		})
	}
}
