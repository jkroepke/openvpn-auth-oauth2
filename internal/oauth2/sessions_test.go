package oauth2_test

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/sessionregistry"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/test/testsuite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSessionRegistry checks that the OIDC identity of a client is recorded at
// interactive login, kept through silent re-authentication, and removed or
// kept dormant at disconnect.
func TestSessionRegistry(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name         string
		validateUser bool
		useSessionID bool
	}{
		{name: "ValidateUser=true", validateUser: true},
		{name: "ValidateUser=false", validateUser: false},
		{name: "ValidateUser=true + UseSessionID=true", validateUser: true, useSessionID: true},
		{name: "ValidateUser=false + UseSessionID=true", useSessionID: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(cancel)

			conf := config.Defaults
			conf.OAuth2.OpenVPNUsername = "token.claims." + testsuite.SubjectClaim
			conf.OpenVPN.AuthTokenUser = false
			conf.OAuth2.Refresh.Enabled = true
			conf.OAuth2.Refresh.ValidateUser = tc.validateUser
			conf.OAuth2.Refresh.UseSessionID = tc.useSessionID

			suite := testsuite.New(&conf)
			errOpenVPNClientCh := suite.SetupMockEnvironment(ctx, t, nil)
			registry := suite.GetSessionRegistry()
			suite.ExpectVersionAndReleaseHold(t)

			t.Cleanup(func() {
				require.NoError(t, suite.GetManagementInterfaceConn().Close())

				select {
				case err := <-errOpenVPNClientCh:
					require.NoError(t, err, suite.Logs())
				case <-time.After(time.Second):
					t.Fatalf("timeout waiting for connection to close. Logs:\n\n%s", suite.Logs())
				}
			})

			user := sessionregistry.Identity{Issuer: suite.GetConfig().OAuth2.Issuer.String(), Subject: "id1"}

			// Interactive login.
			suite.SendMessagef(t, ">CLIENT:CONNECT,1,2\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,common_name=test\r\n"+
				">CLIENT:ENV,session_state=Initial\r\n>CLIENT:ENV,session_id=session_id\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END")

			auth := suite.ReadLine(t)
			require.Contains(t, auth, "client-pending-auth 1 2 \"WEB_AUTH::")
			suite.SendMessagef(t, "SUCCESS: client-pending-auth command succeeded")

			var (
				resp   *http.Response
				reqErr error
				wg     sync.WaitGroup
			)

			wg.Go(func() {
				resp, _, reqErr = testsuite.DoHTTPRequest( //nolint:bodyclose // DoHTTPRequest closes the body.
					t, suite.GetHTTPClient(), "", http.MethodGet, strings.TrimPrefix(strings.Split(auth, `"`)[1], "WEB_AUTH::"), nil, http.NoBody,
				)
			})

			suite.ExpectMessage(t, "client-auth-nt 1 2")
			suite.SendMessagef(t, "SUCCESS: client-auth command succeeded")
			wg.Wait()
			require.NoError(t, reqErr)
			require.Equal(t, http.StatusOK, resp.StatusCode)

			entries := registry.Lookup(user)
			require.Len(t, entries, 1, suite.Logs())
			assert.True(t, entries[0].Connected)
			assert.Equal(t, uint64(1), entries[0].CID)
			assert.Equal(t, "id1", entries[0].Username)

			if tc.useSessionID {
				assert.Equal(t, "session_id", entries[0].OpenVPNSessionID)
			}

			loginIdentity := entries[0].Identity

			// Silent re-authentication keeps the identity.
			suite.SendMessagef(t, ">CLIENT:REAUTH,1,3\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,common_name=test\r\n"+
				">CLIENT:ENV,session_id=session_id\r\n>CLIENT:ENV,session_state=AuthenticatedEmptyUser\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END")
			suite.ExpectMessage(t, "client-auth-nt 1 3")
			suite.SendMessagef(t, "SUCCESS: client-auth command succeeded")

			require.EventuallyWithT(t, func(collect *assert.CollectT) {
				entries := registry.Lookup(user)
				if assert.Len(collect, entries, 1) {
					assert.Equal(collect, loginIdentity, entries[0].Identity)
					assert.Equal(collect, uint64(1), entries[0].CID)
				}
			}, time.Second, 10*time.Millisecond)

			// Disconnect removes the client, or keeps it dormant while its session can reconnect.
			suite.SendMessagef(t, ">CLIENT:DISCONNECT,1\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,common_name=test\r\n"+
				">CLIENT:ENV,session_id=session_id\r\n>CLIENT:ENV,session_state=AuthenticatedEmptyUser\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END")

			require.EventuallyWithT(t, func(collect *assert.CollectT) {
				entries := registry.Lookup(user)
				if !tc.useSessionID {
					assert.Empty(collect, entries)

					return
				}

				if assert.Len(collect, entries, 1) {
					assert.False(collect, entries[0].Connected)
					assert.Equal(collect, "session_id", entries[0].OpenVPNSessionID)
				}
			}, time.Second, 10*time.Millisecond)

			if !tc.useSessionID {
				return
			}

			// Reconnecting with the same session replaces the dormant entry.
			suite.SendMessagef(t, ">CLIENT:CONNECT,2,1\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,common_name=test\r\n"+
				">CLIENT:ENV,session_id=session_id\r\n>CLIENT:ENV,session_state=AuthenticatedEmptyUser\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END")
			suite.ExpectMessage(t, "client-auth-nt 2 1")
			suite.SendMessagef(t, "SUCCESS: client-auth command succeeded")

			require.EventuallyWithT(t, func(collect *assert.CollectT) {
				entries := registry.Lookup(user)
				if assert.Len(collect, entries, 1) {
					assert.True(collect, entries[0].Connected)
					assert.Equal(collect, uint64(2), entries[0].CID)
					assert.Equal(collect, loginIdentity, entries[0].Identity)
				}
			}, time.Second, 10*time.Millisecond)
		})
	}
}
