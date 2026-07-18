package oauth2

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/openvpn/connection"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/tokenstorage"
)

const duplicateUsernameStoragePrefix = "duplicate-username/"

type duplicateUsernameStoredClient struct {
	CommonName        string `json:"common-name,omitempty"`
	SessionID         string `json:"session-id,omitempty"`
	CID               uint64 `json:"cid"`
	KID               uint64 `json:"kid"`
	UsernameIsDefined int    `json:"username-is-defined,omitempty"`
}

type duplicateUsernameSession struct {
	ClientID string                        `json:"client-id"`
	Client   duplicateUsernameStoredClient `json:"client"`
}

func duplicateUsernameSessionKey(username string) string {
	return duplicateUsernameStoragePrefix + "username:" + base64.RawURLEncoding.EncodeToString([]byte(username))
}

func duplicateUsernameClientKey(clientID string) string {
	return duplicateUsernameStoragePrefix + "client:" + clientID
}

// AcceptClientWithDuplicateUsernameSession serializes duplicate-session
// replacement so concurrent authentication attempts cannot both be accepted.
func (c *Client) AcceptClientWithDuplicateUsernameSession(
	ctx context.Context,
	logger *slog.Logger,
	client state.ClientIdentifier,
	clientID, username string,
	accept func() error,
) error {
	if !c.conf.OpenVPN.KillDuplicateUsername || username == "" {
		return accept()
	}

	c.duplicateUsernameMu.Lock()
	defer c.duplicateUsernameMu.Unlock()

	if err := c.killDuplicateUsernameSession(ctx, logger, client, clientID, username); err != nil {
		return err
	}

	if err := accept(); err != nil {
		return err
	}

	c.storeDuplicateUsernameSession(ctx, logger, client, clientID, username)

	return nil
}

func (c *Client) killDuplicateUsernameSession(
	ctx context.Context,
	logger *slog.Logger,
	client state.ClientIdentifier,
	clientID, username string,
) error {
	existingClient, err := c.loadDuplicateUsernameSession(ctx, username)
	if err != nil {
		if errors.Is(err, tokenstorage.ErrNotExists) {
			return nil
		}

		return fmt.Errorf("unable to load duplicate username session: %w", err)
	}

	// Re-authentication for the same OpenVPN client can revisit this path and
	// must not kill the currently active session.
	if existingClient.ClientID == clientID {
		return nil
	}

	logger.LogAttrs(
		ctx, slog.LevelInfo, "kill existing session for duplicate username",
		slog.String("user_username", username),
		slog.Uint64("existing_cid", existingClient.Client.CID),
		slog.String("existing_session_id", existingClient.Client.SessionID),
		slog.Uint64("cid", client.CID),
		slog.String("session_id", client.SessionID),
	)

	err = c.openvpn.KillClient(ctx, logger, existingClient.Client.toStateClientIdentifier())
	if errors.Is(err, connection.ErrClientNotFound) {
		logger.LogAttrs(
			ctx, slog.LevelDebug, "remove stale duplicate username session",
			slog.String("user_username", username),
			slog.Uint64("existing_cid", existingClient.Client.CID),
		)

		c.deleteDuplicateUsernameClientMapping(ctx, logger, existingClient.ClientID)
		c.removeStoredDuplicateUsernameSession(ctx, logger, username, existingClient.ClientID)

		return nil
	}

	if err != nil {
		return fmt.Errorf("unable to kill duplicate username session: %w", err)
	}

	return nil
}

func (c *Client) storeDuplicateUsernameSession(
	ctx context.Context,
	logger *slog.Logger,
	client state.ClientIdentifier,
	clientID, username string,
) {
	if !c.conf.OpenVPN.KillDuplicateUsername || username == "" {
		return
	}

	clientData, err := json.Marshal(duplicateUsernameSession{
		ClientID: clientID,
		Client:   newDuplicateUsernameStoredClient(client),
	})
	if err != nil {
		logger.LogAttrs(ctx, slog.LevelWarn, "unable to marshal duplicate username session", slog.Any("err", err))

		return
	}

	if err = c.storage.Set(ctx, duplicateUsernameSessionKey(username), string(clientData)); err != nil {
		logger.LogAttrs(ctx, slog.LevelWarn, "unable to store duplicate username session", slog.Any("err", err))

		return
	}

	if err = c.storage.Set(ctx, duplicateUsernameClientKey(clientID), username); err != nil {
		if cleanupErr := c.storage.Delete(ctx, duplicateUsernameSessionKey(username)); cleanupErr != nil && !errors.Is(cleanupErr, tokenstorage.ErrNotExists) {
			logger.LogAttrs(ctx, slog.LevelWarn, "unable to clean up duplicate username session after client mapping error", slog.Any("err", cleanupErr))
		}

		logger.LogAttrs(ctx, slog.LevelWarn, "unable to store duplicate username client mapping", slog.Any("err", err))
	}
}

func (c *Client) DeleteDuplicateUsernameSession(ctx context.Context, logger *slog.Logger, clientID string) {
	if !c.conf.OpenVPN.KillDuplicateUsername || clientID == "" {
		return
	}

	c.duplicateUsernameMu.Lock()
	defer c.duplicateUsernameMu.Unlock()

	username, ok := c.loadDuplicateUsernameClientUsername(ctx, logger, clientID)
	if !ok {
		return
	}

	c.deleteDuplicateUsernameClientMapping(ctx, logger, clientID)
	c.removeStoredDuplicateUsernameSession(ctx, logger, username, clientID)
}

func (c *Client) removeStoredDuplicateUsernameSession(ctx context.Context, logger *slog.Logger, username, clientID string) {
	existingClient, err := c.loadDuplicateUsernameSession(ctx, username)
	if err != nil {
		if !errors.Is(err, tokenstorage.ErrNotExists) {
			logger.LogAttrs(ctx, slog.LevelWarn, "unable to load duplicate username session", slog.Any("err", err))
		}

		return
	}

	// A newer session for the same username may already have replaced this
	// mapping, so only remove the username entry when it still points to the
	// disconnecting client.
	if existingClient.ClientID != clientID {
		return
	}

	if err = c.storage.Delete(ctx, duplicateUsernameSessionKey(username)); err != nil && !errors.Is(err, tokenstorage.ErrNotExists) {
		logger.LogAttrs(ctx, slog.LevelWarn, "unable to delete duplicate username session", slog.Any("err", err))
	}
}

func (c *Client) deleteDuplicateUsernameClientMapping(ctx context.Context, logger *slog.Logger, clientID string) {
	if err := c.storage.Delete(ctx, duplicateUsernameClientKey(clientID)); err != nil && !errors.Is(err, tokenstorage.ErrNotExists) {
		logger.LogAttrs(ctx, slog.LevelWarn, "unable to delete duplicate username client mapping", slog.Any("err", err))
	}
}

func (c *Client) loadDuplicateUsernameClientUsername(ctx context.Context, logger *slog.Logger, clientID string) (string, bool) {
	username, err := c.storage.Get(ctx, duplicateUsernameClientKey(clientID))
	if err != nil {
		if !errors.Is(err, tokenstorage.ErrNotExists) {
			logger.LogAttrs(ctx, slog.LevelWarn, "unable to load duplicate username client mapping", slog.Any("err", err))
		}

		return "", false
	}

	return username, true
}

func (c *Client) loadDuplicateUsernameSession(ctx context.Context, username string) (duplicateUsernameSession, error) {
	clientData, err := c.storage.Get(ctx, duplicateUsernameSessionKey(username))
	if err != nil {
		return duplicateUsernameSession{}, fmt.Errorf("load duplicate username session for %q: %w", username, err)
	}

	var session duplicateUsernameSession
	if err = json.Unmarshal([]byte(clientData), &session); err != nil {
		return duplicateUsernameSession{}, fmt.Errorf("unable to parse stored duplicate username session: %w", err)
	}

	return session, nil
}

func newDuplicateUsernameStoredClient(client state.ClientIdentifier) duplicateUsernameStoredClient {
	return duplicateUsernameStoredClient{
		CID:               client.CID,
		KID:               client.KID,
		UsernameIsDefined: client.UsernameIsDefined,
		CommonName:        client.CommonName,
		SessionID:         client.SessionID,
	}
}

func (c duplicateUsernameStoredClient) toStateClientIdentifier() state.ClientIdentifier {
	return state.ClientIdentifier{
		CID:               c.CID,
		KID:               c.KID,
		UsernameIsDefined: c.UsernameIsDefined,
		CommonName:        c.CommonName,
		SessionID:         c.SessionID,
	}
}
