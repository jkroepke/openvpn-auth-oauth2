package oauth2_test

import (
	"bufio"
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
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/generic"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/github"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/google"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func TestRefreshReAuth(t *testing.T) {
	t.Parallel()

	var refreshToken string

	for _, tc := range []struct {
		name                     string
		clientCommonName         string
		nonInteractiveShouldWork bool
		conf                     config.Config
		rt                       http.RoundTripper
	}{
		{
			name:                     "Refresh",
			clientCommonName:         "test",
			nonInteractiveShouldWork: true,
			conf: func() config.Config {
				conf := config.Defaults
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
				conf.OAuth2.Refresh.Enabled = true
				conf.OAuth2.Refresh.ValidateUser = false
				conf.OAuth2.Refresh.UseSessionID = false

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
				conf.OpenVPN.AuthTokenUser = false
				conf.OAuth2.Refresh.Enabled = true
				conf.OAuth2.Refresh.ValidateUser = false
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
			name:                     "Refresh with failed non-interactive authentication",
			clientCommonName:         "test",
			nonInteractiveShouldWork: false,
			conf: func() config.Config {
				conf := config.Defaults
				conf.OpenVPN.AuthTokenUser = false
				conf.OAuth2.Provider = generic.Name
				conf.OAuth2.Refresh.Enabled = true
				conf.OAuth2.Refresh.ValidateUser = true
				conf.OAuth2.Refresh.UseSessionID = false

				return conf
			}(),
			rt: testutils.NewRoundTripperFunc(http.DefaultTransport, func(rt http.RoundTripper, req *http.Request) (*http.Response, error) {
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
				conf.OpenVPN.AuthTokenUser = false
				conf.OAuth2.Provider = generic.Name
				conf.OAuth2.Refresh.Enabled = true
				conf.OAuth2.Refresh.ValidateUser = true
				conf.OAuth2.Refresh.UseSessionID = false

				return conf
			}(),
			rt: testutils.NewRoundTripperFunc(http.DefaultTransport, func(rt http.RoundTripper, req *http.Request) (*http.Response, error) {
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
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(cancel)

			conf, openVPNClient, managementInterface, _, _, httpClient, logger := testutils.SetupMockEnvironment(ctx, t, tc.conf, tc.rt)

			managementInterfaceConn, errOpenVPNClientCh, err := testutils.ConnectToManagementInterface(t, managementInterface, openVPNClient)
			require.NoError(t, err)

			reader := bufio.NewReader(managementInterfaceConn)

			testutils.ExpectVersionAndReleaseHold(t, managementInterfaceConn, reader)

			time.Sleep(time.Millisecond * 100)

			testutils.SendMessagef(t, managementInterfaceConn,
				">CLIENT:CONNECT,1,2\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,common_name=%s\r\n>CLIENT:ENV,session_state=Initial\r\n>CLIENT:ENV,session_id=session_id\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END",
				tc.clientCommonName,
			)

			auth := testutils.ReadLine(t, managementInterfaceConn, reader)
			assert.Contains(t, auth, "client-pending-auth 1 2 \"WEB_AUTH::")
			testutils.SendMessagef(t, managementInterfaceConn, "SUCCESS: %s command succeeded", strings.SplitN(auth, " ", 2)[0])

			authURL := strings.TrimPrefix(strings.Split(auth, `"`)[1], "WEB_AUTH::")

			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, authURL, nil)
			require.NoError(t, err)

			wg := sync.WaitGroup{}
			wg.Add(1)

			var (
				resp   *http.Response
				reqErr error
			)

			go func() {
				defer wg.Done()

				resp, reqErr = httpClient.Do(request) //nolint:bodyclose
			}()

			t.Cleanup(func() {
				require.NoError(t, managementInterfaceConn.Close())

				select {
				case err := <-errOpenVPNClientCh:
					require.NoError(t, err, logger.String())
				case <-time.After(1 * time.Second):
					t.Fatalf("timeout waiting for connection to close. Logs:\n\n%s", logger.String())
				}
			})

			switch {
			case tc.conf.OpenVPN.OverrideUsername:
				testutils.ExpectMessage(t, managementInterfaceConn, reader, "client-auth 1 2")

				if tc.clientCommonName == "" {
					testutils.ExpectMessage(t, managementInterfaceConn, reader, "override-username \"username\"")
				} else {
					testutils.ExpectMessage(t, managementInterfaceConn, reader, "override-username \"test\"")
				}

				testutils.ExpectMessage(t, managementInterfaceConn, reader, "END")
			case tc.conf.OpenVPN.AuthTokenUser:
				testutils.ExpectMessage(t, managementInterfaceConn, reader, "client-auth 1 2")

				if tc.clientCommonName == "" {
					testutils.ExpectMessage(t, managementInterfaceConn, reader, "push \"auth-token-user dXNlcm5hbWUK\"")
				} else {
					testutils.ExpectMessage(t, managementInterfaceConn, reader, "push \"auth-token-user dGVzdA==\"")
				}

				testutils.ExpectMessage(t, managementInterfaceConn, reader, "END")
			default:
				testutils.ExpectMessage(t, managementInterfaceConn, reader, "client-auth-nt 1 2")
			}

			testutils.SendMessagef(t, managementInterfaceConn, "SUCCESS: client-auth command succeeded")

			wg.Wait()

			require.NoError(t, reqErr)
			require.Equal(t, http.StatusOK, resp.StatusCode)

			_, err = io.Copy(io.Discard, resp.Body)
			require.NoError(t, err)

			_ = resp.Body.Close()

			// Testing ReAuth
			testutils.SendMessagef(t, managementInterfaceConn,
				">CLIENT:ESTABLISHED,0\r\n>CLIENT:ENV,common_name=bypass\r\n>CLIENT:ENV,END\r\n",
			)

			// Testing ReAuth
			testutils.SendMessagef(t, managementInterfaceConn,
				">CLIENT:REAUTH,1,3\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,common_name=%s\r\n>CLIENT:ENV,session_id=session_id\r\n>CLIENT:ENV,session_state=AuthenticatedEmptyUser\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END",
				tc.clientCommonName,
			)

			if !tc.conf.OpenVPN.ReAuthentication {
				testutils.ExpectMessage(t, managementInterfaceConn, reader, "client-deny 1 3 \"client re-authentication not enabled\"")
				testutils.SendMessagef(t, managementInterfaceConn, "SUCCESS: client-deny command succeeded")

				return
			}

			if !tc.nonInteractiveShouldWork {
				auth := testutils.ReadLine(t, managementInterfaceConn, reader)
				assert.Contains(t, auth, "client-pending-auth 1 3 \"WEB_AUTH::")
				testutils.SendMessagef(t, managementInterfaceConn, "SUCCESS: %s command succeeded", strings.SplitN(auth, " ", 2)[0])

				return
			}

			testutils.ExpectMessage(t, managementInterfaceConn, reader, "client-auth-nt 1 3")
			testutils.SendMessagef(t, managementInterfaceConn, "SUCCESS: client-auth command succeeded")

			// Testing ReAuth
			testutils.SendMessagef(t, managementInterfaceConn,
				">CLIENT:REAUTH,1,4\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,common_name=%s\r\n>CLIENT:ENV,session_id=session_id\r\n>CLIENT:ENV,session_state=AuthenticatedEmptyUser\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END",
				tc.clientCommonName,
			)

			testutils.ExpectMessage(t, managementInterfaceConn, reader, "client-auth-nt 1 4")
			testutils.SendMessagef(t, managementInterfaceConn, "SUCCESS: client-auth command succeeded")

			// Test Disconnect
			testutils.SendMessagef(t, managementInterfaceConn, ">CLIENT:DISCONNECT,1\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,common_name=test\r\n>CLIENT:ENV,session_id=session_id\r\n>CLIENT:ENV,session_state=AuthenticatedEmptyUser\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END")

			// Test ReAuth after DC
			testutils.SendMessagef(t, managementInterfaceConn, ">CLIENT:REAUTH,1,4\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,common_name=test\r\n>CLIENT:ENV,session_id=session_id\r\n>CLIENT:ENV,session_state=AuthenticatedEmptyUser\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END")

			auth = testutils.ReadLine(t, managementInterfaceConn, reader)

			if conf.OAuth2.Refresh.UseSessionID {
				require.Contains(t, auth, "client-auth-nt 1 4")
			} else {
				require.Contains(t, auth, "client-pending-auth 1 4 \"WEB_AUTH::")
			}

			testutils.SendMessagef(t, managementInterfaceConn, "SUCCESS: %s command succeeded", strings.SplitN(auth, " ", 2)[0])

			// Test ReAuth after DC with different CID
			testutils.SendMessagef(t, managementInterfaceConn, ">CLIENT:CONNECT,2,3\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,common_name=test\r\n>CLIENT:ENV,session_id=session_id\r\n>CLIENT:ENV,session_state=AuthenticatedEmptyUser\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END")

			auth = testutils.ReadLine(t, managementInterfaceConn, reader)

			if conf.OAuth2.Refresh.UseSessionID {
				require.Contains(t, auth, "client-auth-nt 2 3")
			} else {
				require.Contains(t, auth, "client-pending-auth 2 3 \"WEB_AUTH::")
			}

			testutils.SendMessagef(t, managementInterfaceConn, "SUCCESS: %s command succeeded", strings.SplitN(auth, " ", 2)[0])

			// Test ReAuth after DC with different CID with invalid session
			testutils.SendMessagef(t, managementInterfaceConn, ">CLIENT:CONNECT,3,3\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,common_name=test\r\n>CLIENT:ENV,session_id=session_id\r\n>CLIENT:ENV,session_state=Expired\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END")

			auth = testutils.ReadLine(t, managementInterfaceConn, reader)

			if conf.OAuth2.Refresh.UseSessionID {
				assert.Equal(t, fmt.Sprintf(`client-deny 3 3 "%s"`, openvpn.ReasonStateExpiredOrInvalid), auth)
			} else {
				assert.Contains(t, auth, `client-pending-auth 3 3 "WEB_AUTH::`)
			}

			testutils.SendMessagef(t, managementInterfaceConn, "SUCCESS: %s command succeeded", strings.SplitN(auth, " ", 2)[0])
		})
	}
}
