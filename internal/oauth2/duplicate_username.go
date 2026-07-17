package oauth2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/tokenstorage"
)

const duplicateUsernameStoragePrefix = "duplicate-username:"

type duplicateUsernameSession struct {
	Client   state.ClientIdentifier `json:"client"`
	ClientID string                 `json:"client-id"`
}

func duplicateUsernameSessionKey(username string) string {
	return duplicateUsernameStoragePrefix + "username:" + username
}

func duplicateUsernameClientKey(clientID string) string {
	return duplicateUsernameStoragePrefix + "client:" + clientID
}

func (c *Client) KillDuplicateUsernameSession(
	ctx context.Context,
	logger *slog.Logger,
	client state.ClientIdentifier,
	clientID, username string,
) error {
	if !c.conf.OpenVPN.KillDuplicateUsername || username == "" {
		return nil
	}

	existingClient, err := c.loadDuplicateUsernameSession(ctx, username)
	if err != nil {
		if errors.Is(err, tokenstorage.ErrNotExists) {
			return nil
		}

		return fmt.Errorf("unable to load duplicate username session: %w", err)
	}

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

	if err = c.openvpn.KillClient(ctx, logger, existingClient.Client); err != nil {
		return fmt.Errorf("unable to kill duplicate username session: %w", err)
	}

	return nil
}

func (c *Client) StoreDuplicateUsernameSession(
	ctx context.Context,
	logger *slog.Logger,
	client state.ClientIdentifier,
	clientID, username string,
) {
	if !c.conf.OpenVPN.KillDuplicateUsername || username == "" {
		return
	}

	clientData, err := json.Marshal(duplicateUsernameSession{
		Client:   client,
		ClientID: clientID,
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
		logger.LogAttrs(ctx, slog.LevelWarn, "unable to store duplicate username client mapping", slog.Any("err", err))
	}
}

func (c *Client) DeleteDuplicateUsernameSession(
	ctx context.Context,
	logger *slog.Logger,
	clientID string,
) {
	if !c.conf.OpenVPN.KillDuplicateUsername || clientID == "" {
		return
	}

	username, err := c.storage.Get(ctx, duplicateUsernameClientKey(clientID))
	if err != nil {
		if !errors.Is(err, tokenstorage.ErrNotExists) {
			logger.LogAttrs(ctx, slog.LevelWarn, "unable to load duplicate username client mapping", slog.Any("err", err))
		}

		return
	}

	if err = c.storage.Delete(ctx, duplicateUsernameClientKey(clientID)); err != nil && !errors.Is(err, tokenstorage.ErrNotExists) {
		logger.LogAttrs(ctx, slog.LevelWarn, "unable to delete duplicate username client mapping", slog.Any("err", err))
	}

	existingClient, err := c.loadDuplicateUsernameSession(ctx, username)
	if err != nil {
		if !errors.Is(err, tokenstorage.ErrNotExists) {
			logger.LogAttrs(ctx, slog.LevelWarn, "unable to load duplicate username session", slog.Any("err", err))
		}

		return
	}

	if existingClient.ClientID != clientID {
		return
	}

	if err = c.storage.Delete(ctx, duplicateUsernameSessionKey(username)); err != nil && !errors.Is(err, tokenstorage.ErrNotExists) {
		logger.LogAttrs(ctx, slog.LevelWarn, "unable to delete duplicate username session", slog.Any("err", err))
	}
}

func (c *Client) loadDuplicateUsernameSession(ctx context.Context, username string) (duplicateUsernameSession, error) {
	clientData, err := c.storage.Get(ctx, duplicateUsernameSessionKey(username))
	if err != nil {
		return duplicateUsernameSession{}, err
	}

	var session duplicateUsernameSession
	if err = json.Unmarshal([]byte(clientData), &session); err != nil {
		return duplicateUsernameSession{}, fmt.Errorf("unable to parse duplicate username session: %w", err)
	}

	return session, nil
}
