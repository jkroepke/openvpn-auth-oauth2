//nolint:testpackage
package oauth2

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/crypto"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/openvpn/connection"
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

func TestAcceptOAuth2ClientReplacesStaleDuplicateUsernameSession(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	conf := config.Defaults
	conf.OpenVPN.KillDuplicateUsername = true

	storage := tokenstorage.NewInMemoryWithGC("1234567890123456", time.Hour, 0)
	openVPNClient := &recordingOpenVPNClient{
		killErr: fmt.Errorf("kill failed: %w", connection.ErrClientNotFound),
	}
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

	secondRecorder := httptest.NewRecorder()
	client.acceptOAuth2Client(ctx, secondRecorder, codeExchangeRequest{
		logger:   slog.New(slog.DiscardHandler),
		clientID: "2",
		username: "alice",
		session:  state.State{Client: state.ClientIdentifier{CID: 2, KID: 1}},
	})
	require.Equal(t, http.StatusOK, secondRecorder.Code)

	require.Equal(t, []string{"accept:1:alice", "kill:1", "accept:2:alice"}, openVPNClient.operations)

	_, err := storage.Get(ctx, duplicateUsernameClientKey("1"))
	require.ErrorIs(t, err, tokenstorage.ErrNotExists)

	existingClient, err := client.loadDuplicateUsernameSession(ctx, "alice")
	require.NoError(t, err)
	require.Equal(t, "2", existingClient.ClientID)
}

func TestAcceptOAuth2ClientRejectsReplacementWhenKillFails(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	conf := config.Defaults
	conf.OpenVPN.KillDuplicateUsername = true

	storage := tokenstorage.NewInMemoryWithGC("1234567890123456", time.Hour, 0)
	openVPNClient := &recordingOpenVPNClient{killErr: errors.New("management connection failed")}
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

	secondRecorder := httptest.NewRecorder()
	client.acceptOAuth2Client(ctx, secondRecorder, codeExchangeRequest{
		logger:   slog.New(slog.DiscardHandler),
		clientID: "2",
		username: "alice",
		session:  state.State{Client: state.ClientIdentifier{CID: 2, KID: 1}},
	})
	require.Equal(t, http.StatusInternalServerError, secondRecorder.Code)

	require.Equal(t, []string{"accept:1:alice", "kill:1"}, openVPNClient.operations)

	existingClient, err := client.loadDuplicateUsernameSession(ctx, "alice")
	require.NoError(t, err)
	require.Equal(t, "1", existingClient.ClientID)
}

func TestAcceptOAuth2ClientSerializesDuplicateUsernameSessions(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	conf := config.Defaults
	conf.OpenVPN.KillDuplicateUsername = true

	storage := tokenstorage.NewInMemoryWithGC("1234567890123456", time.Hour, 0)
	openVPNClient := &blockingOpenVPNClient{
		recordingOpenVPNClient: recordingOpenVPNClient{},
		acceptStarted:          make(chan uint64, 2),
		releaseFirst:           make(chan struct{}),
	}
	client := Client{
		conf:    &conf,
		openvpn: openVPNClient,
		storage: storage,
	}

	var wg sync.WaitGroup
	wg.Go(func() {
		client.acceptOAuth2Client(ctx, httptest.NewRecorder(), codeExchangeRequest{
			logger:   slog.New(slog.DiscardHandler),
			clientID: "1",
			username: "alice",
			session:  state.State{Client: state.ClientIdentifier{CID: 1, KID: 1}},
		})
	})

	require.Equal(t, uint64(1), <-openVPNClient.acceptStarted)

	secondStarted := make(chan struct{})

	wg.Go(func() {
		close(secondStarted)
		client.acceptOAuth2Client(ctx, httptest.NewRecorder(), codeExchangeRequest{
			logger:   slog.New(slog.DiscardHandler),
			clientID: "2",
			username: "alice",
			session:  state.State{Client: state.ClientIdentifier{CID: 2, KID: 1}},
		})
	})
	<-secondStarted

	select {
	case cid := <-openVPNClient.acceptStarted:
		t.Fatalf("client %d reached acceptance before the first session was stored", cid)
	case <-time.After(50 * time.Millisecond):
	}

	close(openVPNClient.releaseFirst)

	select {
	case cid := <-openVPNClient.acceptStarted:
		require.Equal(t, uint64(2), cid)
	case <-time.After(time.Second):
		t.Fatal("second client did not reach acceptance")
	}

	wg.Wait()
	require.Equal(t, []string{"accept:1:alice", "kill:1", "accept:2:alice"}, openVPNClient.operations)
}

func TestOAuth2ProfileSubmitKillsExistingSessionForSameUsername(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	conf := config.Defaults
	conf.OpenVPN.KillDuplicateUsername = true

	storage := tokenstorage.NewInMemoryWithGC("1234567890123456", time.Hour, 0)
	stateCrypto := crypto.New("1234567890123456")
	openVPNClient := &recordingOpenVPNClient{}
	client := Client{
		conf:        &conf,
		openvpn:     openVPNClient,
		storage:     storage,
		stateCrypto: stateCrypto,
		logger:      slog.New(slog.DiscardHandler),
	}

	client.acceptOAuth2Client(ctx, httptest.NewRecorder(), codeExchangeRequest{
		logger:   slog.New(slog.DiscardHandler),
		clientID: "1",
		username: "alice",
		session:  state.State{Client: state.ClientIdentifier{CID: 1, KID: 1}},
	})

	secondSession := state.State{Client: state.ClientIdentifier{CID: 2, KID: 1}}
	encryptedState, err := state.Encrypt(stateCrypto, secondSession)
	require.NoError(t, err)

	encryptedToken, err := client.createProfileSelectorToken(encryptedState, "alice", []string{"profile"})
	require.NoError(t, err)
	require.NoError(t, client.storeProfileSelectorToken(ctx, encryptedToken, "2"))

	form := url.Values{"token": {encryptedToken}, "profile": {"profile"}}
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/oauth2/profile-submit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	recorder := httptest.NewRecorder()

	client.OAuth2ProfileSubmit().ServeHTTP(recorder, req)

	require.Equal(t, http.StatusOK, recorder.Code)
	require.Equal(t, []string{"accept:1:alice", "kill:1", "accept:2:alice"}, openVPNClient.operations)
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
	killErr    error
}

type blockingOpenVPNClient struct {
	recordingOpenVPNClient

	acceptStarted chan uint64
	releaseFirst  chan struct{}
}

func (c *blockingOpenVPNClient) AcceptClient(
	ctx context.Context,
	logger *slog.Logger,
	client state.ClientIdentifier,
	username string,
	clientConfigNames ...string,
) error {
	if err := c.recordingOpenVPNClient.AcceptClient(ctx, logger, client, username, clientConfigNames...); err != nil {
		return err
	}

	c.acceptStarted <- client.CID

	if client.CID == 1 {
		<-c.releaseFirst
	}

	return nil
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

	return c.killErr
}
