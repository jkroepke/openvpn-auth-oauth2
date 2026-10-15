package oauth2_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/revocation"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/sessionregistry"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/ssf"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/ssf/ssftest"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/test/testsuite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	xoauth2 "golang.org/x/oauth2"
)

type revocationSuite struct {
	*testsuite.Suite

	enforcer *revocation.Enforcer
	user     sessionregistry.Identity
}

func newRevocationSuite(t *testing.T, validateUser, useSessionID bool) *revocationSuite {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	conf := config.Defaults
	conf.OAuth2.OpenVPNUsername = "token.claims." + testsuite.SubjectClaim
	conf.OpenVPN.AuthTokenUser = false
	conf.OAuth2.Refresh.Enabled = true
	conf.OAuth2.Refresh.ValidateUser = validateUser
	conf.OAuth2.Refresh.UseSessionID = useSessionID
	conf.SSF.UserLevelRevocation = true

	suite := testsuite.New(&conf)
	errOpenVPNClientCh := suite.SetupMockEnvironment(ctx, t, nil)
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

	return &revocationSuite{
		Suite: suite,
		enforcer: revocation.New(
			suite.GetLogger(), suite.GetConfig(), suite.GetSessionRegistry(), suite.GetOAuth2Client(), suite.GetOpenVPNClient(), nil,
		),
		user: sessionregistry.Identity{Issuer: suite.GetConfig().OAuth2.Issuer.String(), Subject: "id1"},
	}
}

// connect sends a CLIENT:CONNECT with session_id and returns the pending auth URL.
func (s *revocationSuite) connect(t *testing.T, cid, kid uint64, sessionState string) string {
	t.Helper()

	s.SendMessagef(t, ">CLIENT:CONNECT,%d,%d\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,common_name=test\r\n"+
		">CLIENT:ENV,session_state=%s\r\n>CLIENT:ENV,session_id=session_id\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END",
		cid, kid, sessionState)

	auth := s.ReadLine(t)
	require.Contains(t, auth, "client-pending-auth "+strings.Join([]string{u64(cid), u64(kid)}, " ")+` "WEB_AUTH::`, s.Logs())
	s.SendMessagef(t, "SUCCESS: client-pending-auth command succeeded")

	return strings.TrimPrefix(strings.Split(auth, `"`)[1], "WEB_AUTH::")
}

// login completes the browser login at authURL while expect handles the
// management interface, and returns the HTTP status of the result page.
func (s *revocationSuite) login(t *testing.T, authURL string, expect func()) int {
	t.Helper()

	var (
		resp   *http.Response
		reqErr error
		wg     sync.WaitGroup
	)

	wg.Go(func() {
		resp, _, reqErr = testsuite.DoHTTPRequest( //nolint:bodyclose // DoHTTPRequest closes the body.
			t, s.GetHTTPClient(), "", http.MethodGet, authURL, nil, http.NoBody,
		)
	})

	expect()
	wg.Wait()
	require.NoError(t, reqErr)

	return resp.StatusCode
}

// revoke applies a user-level revocation and answers the expected client-kill commands.
func (s *revocationSuite) revoke(t *testing.T, killed ...uint64) int {
	t.Helper()

	type result struct {
		err   error
		count int
	}

	resultCh := make(chan result, 1)

	go func() {
		count, err := s.enforcer.Revoke(t.Context(), s.user)
		resultCh <- result{count: count, err: err}
	}()

	for _, cid := range killed {
		s.ExpectMessage(t, "client-kill "+u64(cid)+" HALT")
		s.SendMessagef(t, "SUCCESS: client-kill command succeeded")
	}

	select {
	case res := <-resultCh:
		require.NoError(t, res.err, s.Logs())

		return res.count
	case <-time.After(time.Second):
		t.Fatalf("timeout waiting for revocation. Logs:\n\n%s", s.Logs())

		return 0
	}
}

func staticToken(token string) xoauth2.TokenSource {
	return xoauth2.StaticTokenSource(&xoauth2.Token{AccessToken: token})
}

func u64(value uint64) string {
	return strconv.FormatUint(value, 10)
}

// TestSessionRevocation checks that a revoked session is terminated and that
// the client has to log in interactively when it reconnects.
func TestSessionRevocation(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name         string
		validateUser bool
		useSessionID bool
	}{
		{name: "ValidateUser=true", validateUser: true},
		{name: "ValidateUser=false"},
		{name: "ValidateUser=true + UseSessionID=true", validateUser: true, useSessionID: true},
		{name: "ValidateUser=false + UseSessionID=true", useSessionID: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			suite := newRevocationSuite(t, tc.validateUser, tc.useSessionID)

			authURL := suite.connect(t, 1, 2, "Initial")
			status := suite.login(t, authURL, func() {
				suite.ExpectMessage(t, "client-auth-nt 1 2")
				suite.SendMessagef(t, "SUCCESS: client-auth command succeeded")
			})
			require.Equal(t, http.StatusOK, status)

			assert.Equal(t, 1, suite.revoke(t, 1))

			suite.SendMessagef(t, ">CLIENT:DISCONNECT,1\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,common_name=test\r\n"+
				">CLIENT:ENV,session_id=session_id\r\n>CLIENT:ENV,session_state=AuthenticatedEmptyUser\r\n>CLIENT:ENV,END")

			require.EventuallyWithT(t, func(collect *assert.CollectT) {
				assert.Equal(collect, 0, suite.GetSessionRegistry().Len())
			}, time.Second, 10*time.Millisecond)

			// The refresh state is gone, so reconnecting with the same session needs an interactive login.
			suite.connect(t, 2, 1, "AuthenticatedEmptyUser")
		})
	}
}

// TestSSFSessionRevocation runs the receiver against the mock transmitter:
// a session-revoked event for the logged-in user terminates the client.
func TestSSFSessionRevocation(t *testing.T) {
	t.Parallel()

	suite := newRevocationSuite(t, true, false)
	transmitter := ssftest.New(t)

	issuer, err := url.Parse(transmitter.Issuer())
	require.NoError(t, err)

	discovery, err := ssf.Discover(t.Context(), transmitter.Client(), issuer, staticToken(transmitter.Token()))
	require.NoError(t, err)

	receiver := ssf.NewReceiver(slog.New(slog.DiscardHandler), ssf.ReceiverConfig{
		Client: transmitter.Client(),
		Verifier: ssf.NewVerifier(ssf.VerifierConfig{
			KeySet:   rp.NewRemoteKeySet(transmitter.Client(), discovery.Metadata.JWKSURI),
			Issuer:   discovery.Metadata.Issuer,
			Audience: discovery.Stream.Audience,
			MaxAge:   time.Hour,
		}),
		Handler:     suite.enforcer,
		Endpoint:    discovery.Stream.Delivery.EndpointURL,
		TokenSource: staticToken(transmitter.Token()),
		Interval:    10 * time.Millisecond,
		MaxEvents:   10,
	})

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)

	go func() { done <- receiver.Run(ctx) }()

	t.Cleanup(func() {
		cancel()
		require.NoError(t, <-done)
	})

	authURL := suite.connect(t, 1, 2, "Initial")
	status := suite.login(t, authURL, func() {
		suite.ExpectMessage(t, "client-auth-nt 1 2")
		suite.SendMessagef(t, "SUCCESS: client-auth command succeeded")
	})
	require.Equal(t, http.StatusOK, status)

	jti := transmitter.EmitSessionRevoked(t, ssftest.IssSub(suite.user.Issuer, suite.user.Subject))

	suite.ExpectMessage(t, "client-kill 1 HALT")
	suite.SendMessagef(t, "SUCCESS: client-kill command succeeded")

	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		assert.Contains(collect, transmitter.Acked(), jti)
	}, 5*time.Second, 10*time.Millisecond)

	assert.Equal(t, 0, suite.GetSessionRegistry().Len())
}
