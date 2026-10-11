//nolint:testpackage
package oauth2

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/deny"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/tokenstorage"
	"github.com/stretchr/testify/require"
)

func TestAcceptOAuth2ClientDoesNotStoreRefreshStateOnAcceptError(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	conf := config.Defaults
	conf.OAuth2.Refresh.Enabled = true
	conf.OAuth2.Refresh.ValidateUser = false

	storage := newInMemoryStorage(t)
	openVPNClient := &failingOpenVPNClient{
		acceptErr: deny.Wrap(deny.ClientConfigUnavailable, errors.New("client configuration not found")),
	}
	client := Client{
		conf:    &conf,
		openvpn: openVPNClient,
		storage: storage,
	}

	recorder := httptest.NewRecorder()
	client.acceptOAuth2Client(ctx, recorder, codeExchangeRequest{
		logger:   slog.New(slog.DiscardHandler),
		clientID: "1",
		session:  state.State{Client: state.ClientIdentifier{CID: 1, KID: 2}},
	}, "missing")

	require.Equal(t, http.StatusInternalServerError, recorder.Code)
	require.Equal(t, []deny.Reason{deny.ClientConfigUnavailable}, openVPNClient.denyReasons)

	_, err := storage.Get(ctx, "1")
	require.ErrorIs(t, err, tokenstorage.ErrNotExists)
}

func TestAcceptOAuth2ClientDeniesWithFallbackReason(t *testing.T) {
	t.Parallel()

	conf := config.Defaults
	openVPNClient := &failingOpenVPNClient{acceptErr: errors.New("connection lost")}
	client := Client{
		conf:    &conf,
		openvpn: openVPNClient,
		storage: newInMemoryStorage(t),
	}

	recorder := httptest.NewRecorder()
	client.acceptOAuth2Client(t.Context(), recorder, codeExchangeRequest{
		logger:  slog.New(slog.DiscardHandler),
		session: state.State{Client: state.ClientIdentifier{CID: 1, KID: 2}},
	})

	require.Equal(t, http.StatusInternalServerError, recorder.Code)
	require.Equal(t, []deny.Reason{deny.AcceptFailed}, openVPNClient.denyReasons)
}

type failingOpenVPNClient struct {
	acceptErr   error
	denyReasons []deny.Reason
}

func (c *failingOpenVPNClient) AcceptClient(
	context.Context,
	*slog.Logger,
	state.ClientIdentifier,
	string,
	...string,
) error {
	return c.acceptErr
}

func (c *failingOpenVPNClient) DenyClient(_ context.Context, _ *slog.Logger, _ state.ClientIdentifier, reason deny.Reason) {
	c.denyReasons = append(c.denyReasons, reason)
}
