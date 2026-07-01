//nolint:testpackage
package oauth2

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/tokenstorage"
	"github.com/stretchr/testify/require"
)

func TestAcceptOAuth2ClientDoesNotStoreRefreshStateOnAcceptError(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	conf := config.Defaults
	conf.OAuth2.Refresh.Enabled = true
	conf.OAuth2.Refresh.ValidateUser = false

	storage := tokenstorage.NewInMemoryWithGC("1234567890123456", time.Hour, 0)
	client := Client{
		conf:    &conf,
		openvpn: failingOpenVPNClient{},
		storage: storage,
	}

	recorder := httptest.NewRecorder()
	client.acceptOAuth2Client(ctx, recorder, codeExchangeRequest{
		logger:   slog.New(slog.DiscardHandler),
		clientID: "1",
		session:  state.State{Client: state.ClientIdentifier{CID: 1, KID: 2}},
	}, "missing")

	require.Equal(t, http.StatusInternalServerError, recorder.Code)

	_, err := storage.Get(ctx, "1")
	require.ErrorIs(t, err, tokenstorage.ErrNotExists)
}

type failingOpenVPNClient struct{}

func (failingOpenVPNClient) AcceptClient(
	context.Context,
	*slog.Logger,
	state.ClientIdentifier,
	string,
	...string,
) error {
	return errors.New("client configuration not found")
}

func (failingOpenVPNClient) DenyClient(context.Context, *slog.Logger, state.ClientIdentifier, string) {
}
