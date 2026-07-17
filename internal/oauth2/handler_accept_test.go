//nolint:testpackage
package oauth2

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config"
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

func TestAcceptOAuth2ClientKillsExistingSessionForSameUsername(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	conf := config.Defaults
	conf.OpenVPN.KillDuplicateUsername = true

	storage := tokenstorage.NewInMemoryWithGC("1234567890123456", time.Hour, 0)
	openVPNClient := &recordingOpenVPNClient{}
	client := Client{
		conf:    &conf,
		openvpn: openVPNClient,
		storage: storage,
	}

	firstRecorder := httptest.NewRecorder()
	client.acceptOAuth2Client(ctx, firstRecorder, codeExchangeRequest{
		logger:   slog.New(slog.DiscardHandler),
		clientID: "1",
		username: "alice",
		session:  state.State{Client: state.ClientIdentifier{CID: 1, KID: 1}},
	})
	require.Equal(t, http.StatusOK, firstRecorder.Code)

	sameRecorder := httptest.NewRecorder()
	client.acceptOAuth2Client(ctx, sameRecorder, codeExchangeRequest{
		logger:   slog.New(slog.DiscardHandler),
		clientID: "1",
		username: "alice",
		session:  state.State{Client: state.ClientIdentifier{CID: 1, KID: 2}},
	})
	require.Equal(t, http.StatusOK, sameRecorder.Code)

	secondRecorder := httptest.NewRecorder()
	client.acceptOAuth2Client(ctx, secondRecorder, codeExchangeRequest{
		logger:   slog.New(slog.DiscardHandler),
		clientID: "2",
		username: "alice",
		session:  state.State{Client: state.ClientIdentifier{CID: 2, KID: 1}},
	})
	require.Equal(t, http.StatusOK, secondRecorder.Code)

	require.Equal(t, []string{
		"accept:1:alice",
		"accept:1:alice",
		"kill:1",
		"accept:2:alice",
	}, openVPNClient.operations)
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

func (failingOpenVPNClient) KillClient(context.Context, *slog.Logger, state.ClientIdentifier) error {
	return nil
}

type recordingOpenVPNClient struct {
	mu         sync.Mutex
	operations []string
}

func (c *recordingOpenVPNClient) AcceptClient(
	_ context.Context,
	_ *slog.Logger,
	client state.ClientIdentifier,
	username string,
	_ ...string,
) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.operations = append(c.operations, "accept:"+strconv.FormatUint(client.CID, 10)+":"+username)

	return nil
}

func (c *recordingOpenVPNClient) DenyClient(context.Context, *slog.Logger, state.ClientIdentifier, string) {
}

func (c *recordingOpenVPNClient) KillClient(_ context.Context, _ *slog.Logger, client state.ClientIdentifier) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.operations = append(c.operations, "kill:"+strconv.FormatUint(client.CID, 10))

	return nil
}
