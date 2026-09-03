package oauth2

import (
	"context"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config"
	configtypes "github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config/types"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/crypto"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/test/testlogger"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/tokenstorage"
	"github.com/stretchr/testify/require"
)

func TestWithIDTokenClaimsLoggerOmitsUnrestrictedClaims(t *testing.T) {
	t.Parallel()

	logger := testlogger.New()
	tokens := &idtoken.IDToken{
		IDTokenClaims: &idtoken.Claims{
			Claims: map[string]any{"custom_sensitive_claim": "secret-custom-claim"},
		},
	}
	tokens.IDTokenClaims.Subject = "subject"

	withIDTokenClaimsLogger(logger.Logger(), tokens).Info("test message")

	require.Contains(t, logger.String(), "idtoken_subject=subject")
	require.NotContains(t, logger.String(), "custom_sensitive_claim")
	require.NotContains(t, logger.String(), "secret-custom-claim")
}

func TestHandleClientConfigSelectorDeniesClientOnRenderError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		template configtypes.Template
		writer   http.ResponseWriter
	}{
		{
			name: "template execution",
			template: configtypes.Template{Template: template.Must(
				template.New("index.gohtml").Parse(`{{ slice .message 999 }}`),
			)},
			writer: httptest.NewRecorder(),
		},
		{
			name:     "response write",
			template: config.Defaults.HTTP.Template,
			writer: &errorResponseWriter{
				err: errors.New("write failed"),
			},
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			conf := config.Defaults
			conf.HTTP.Template = testCase.template
			openVPNClient := &recordingOpenVPNClient{}
			client := Client{
				conf:        &conf,
				logger:      slog.New(slog.DiscardHandler),
				openvpn:     openVPNClient,
				stateCrypto: crypto.New("1234567890123456"),
				storage: tokenstorage.NewInMemoryWithGC(
					"1234567890123456",
					time.Hour,
					0,
				),
			}
			session := state.State{Client: state.ClientIdentifier{CID: 1, KID: 2}}

			handled := client.handleClientConfigSelector(t.Context(), testCase.writer, codeExchangeRequest{
				logger:         slog.New(slog.DiscardHandler),
				encryptedState: "state",
				session:        session,
				clientID:       "1",
			}, []string{"profile-a", "profile-b"})

			require.True(t, handled)
			require.Zero(t, openVPNClient.acceptCount)
			require.Equal(t, 1, openVPNClient.denyCount)
			require.Equal(t, session.Client, openVPNClient.deniedClient)
			require.Equal(t, "internal error", openVPNClient.denyReason)
		})
	}
}

type errorResponseWriter struct {
	err error
}

func (errorResponseWriter) Header() http.Header {
	return http.Header{}
}

func (w errorResponseWriter) Write([]byte) (int, error) {
	return 0, w.err
}

func (errorResponseWriter) WriteHeader(int) {
}

type recordingOpenVPNClient struct {
	deniedClient state.ClientIdentifier
	denyReason   string
	acceptCount  int
	denyCount    int
}

func (c *recordingOpenVPNClient) AcceptClient(
	context.Context,
	*slog.Logger,
	state.ClientIdentifier,
	string,
	...string,
) error {
	c.acceptCount++

	return nil
}

func (c *recordingOpenVPNClient) DenyClient(
	_ context.Context,
	_ *slog.Logger,
	client state.ClientIdentifier,
	reason string,
) {
	c.denyCount++
	c.deniedClient = client
	c.denyReason = reason
}

func TestWriteHTTPErrorDoesNotExposeTechnicalDetails(t *testing.T) {
	t.Parallel()

	conf := config.Defaults
	client := Client{conf: &conf}
	recorder := httptest.NewRecorder()

	client.writeHTTPError(
		t.Context(),
		recorder,
		slog.New(slog.DiscardHandler),
		http.StatusInternalServerError,
		"profile selector template",
		"sensitive render detail",
	)

	require.Contains(t, recorder.Body.String(), "Please contact your administrator")
	require.NotContains(t, recorder.Body.String(), "profile selector template")
	require.NotContains(t, recorder.Body.String(), "sensitive render detail")
}
