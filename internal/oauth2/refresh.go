package oauth2

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn/connection"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/tokenstorage"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
)

// RefreshClientAuth initiates non-interactive authentication against the SSO provider.
func (c *Client) RefreshClientAuth(ctx context.Context, logger *slog.Logger, client connection.Client) (types.UserInfo, *idtoken.IDToken, bool, error) {
	clientID := c.getRefreshClientID(client)

	refreshToken, hasRefreshToken, err := c.loadRefreshToken(ctx, logger, clientID)
	if err != nil {
		return types.UserInfo{}, nil, false, err
	}

	if !hasRefreshToken {
		return types.UserInfo{}, nil, false, nil
	}

	if !c.conf.OAuth2.Refresh.ValidateUser {
		logger.LogAttrs(ctx, slog.LevelInfo, "successful non-interactive authentication via internal token")

		return types.UserInfo{}, nil, true, nil
	}

	ctx = c.withRefreshNonce(ctx, clientID)

	tokens, err := c.refreshTokens(ctx, logger, refreshToken)
	if err != nil {
		return types.UserInfo{}, nil, false, err
	}

	oAuth2State := refreshOAuth2State(client)

	user, err := c.validateRefreshedUser(ctx, logger, oAuth2State, tokens)
	if err != nil {
		return types.UserInfo{}, nil, false, err
	}

	logger.LogAttrs(ctx, slog.LevelInfo, "successful authenticate via refresh token")

	c.storeRotatedRefreshToken(ctx, logger, oAuth2State, clientID, tokens)

	return user, tokens, true, nil
}

// getRefreshClientID returns the token storage key for a reconnecting OpenVPN client.
func (c *Client) getRefreshClientID(client connection.Client) string {
	if c.conf.OAuth2.Refresh.UseSessionID && client.SessionID != "" {
		return client.SessionID
	}

	return strconv.FormatUint(client.CID, 10)
}

// loadRefreshToken returns the stored refresh token and whether it can be used.
func (c *Client) loadRefreshToken(ctx context.Context, logger *slog.Logger, clientID string) (string, bool, error) {
	refreshToken, err := c.storage.Get(ctx, clientID)
	if err != nil {
		if errors.Is(err, tokenstorage.ErrNotExists) {
			logger.LogAttrs(ctx, slog.LevelDebug, "no refresh token found for client "+clientID)

			return "", false, nil
		}

		return "", false, fmt.Errorf("error from token store: %w", err)
	}

	if refreshToken == "" {
		logger.LogAttrs(ctx, slog.LevelWarn, "stored refresh token is empty. This should not happen. Please report this issue.")

		return "", false, nil
	}

	return refreshToken, true, nil
}

// withRefreshNonce adds a nonce to the refresh context when nonce validation is configured.
func (c *Client) withRefreshNonce(ctx context.Context, clientID string) context.Context {
	if !c.conf.OAuth2.Nonce {
		return ctx
	}

	return context.WithValue(ctx, types.CtxNonce{}, c.getNonce(clientID))
}

// refreshTokens exchanges a stored refresh token for fresh OAuth2 tokens.
func (c *Client) refreshTokens(ctx context.Context, logger *slog.Logger, refreshToken string) (*idtoken.IDToken, error) {
	logger.LogAttrs(ctx, slog.LevelInfo, "initiate non-interactive authentication via refresh token")

	tokens, err := c.provider.Refresh(ctx, logger, c.relyingParty, refreshToken)
	if err != nil {
		return nil, fmt.Errorf("error from non-interactive authentication via refresh token: %w", err)
	}

	return tokens, nil
}

// refreshOAuth2State converts an OpenVPN client into the OAuth2 state used for validation.
func refreshOAuth2State(client connection.Client) state.State {
	return state.State{
		Client: state.ClientIdentifier{
			CID:        client.CID,
			KID:        client.KID,
			SessionID:  client.SessionID,
			CommonName: client.CommonName,
		},
		IPAddr:       client.IPAddr,
		IPPort:       client.IPPort,
		SessionState: client.SessionState,
	}
}

// validateRefreshedUser resolves and validates user data for a refreshed token set.
func (c *Client) validateRefreshedUser(
	ctx context.Context,
	logger *slog.Logger,
	oAuth2State state.State,
	tokens *idtoken.IDToken,
) (types.UserInfo, error) {
	userInfo, err := c.refreshedUserInfo(ctx, tokens)
	if err != nil {
		return types.UserInfo{}, err
	}

	user, err := c.provider.GetUser(ctx, logger, tokens, userInfo)
	if err != nil {
		return types.UserInfo{}, fmt.Errorf("error fetch user data: %w", err)
	}

	if err := c.provider.CheckUser(ctx, oAuth2State, user, tokens); err != nil {
		return types.UserInfo{}, fmt.Errorf("error check user data: %w", err)
	}

	if err = c.CheckTokenCEL(CELAuthModeNonInteractive, oAuth2State, tokens); err != nil {
		return types.UserInfo{}, fmt.Errorf("error cel validation: %w", err)
	}

	return user, nil
}

// refreshedUserInfo fetches UserInfo for refreshed tokens when UserInfo support is enabled.
func (c *Client) refreshedUserInfo(ctx context.Context, tokens *idtoken.IDToken) (*types.UserInfo, error) {
	if !c.conf.OAuth2.UserInfo {
		return nil, nil //nolint:nilnil // UserInfo is optional and absent when disabled.
	}

	userInfo, err := rp.Userinfo[*types.UserInfo](ctx, tokens.AccessToken, tokens.TokenType, tokens.IDTokenClaims.GetSubject(), c.relyingParty)
	if err != nil {
		return nil,
			fmt.Errorf("error during UserInfo request (subject: %s, token type: %s): %w", tokens.IDTokenClaims.GetSubject(), tokens.TokenType, err)
	}

	return userInfo, nil
}

// storeRotatedRefreshToken stores the newest refresh token returned by the provider.
func (c *Client) storeRotatedRefreshToken(
	ctx context.Context,
	logger *slog.Logger,
	oAuth2State state.State,
	clientID string,
	tokens *idtoken.IDToken,
) {
	refreshToken, err := c.provider.GetRefreshToken(tokens)
	if err != nil {
		c.logRefreshTokenError(ctx, logger, oAuth2State, err)

		return
	}

	if refreshToken == "" {
		logger.LogAttrs(ctx, slog.LevelWarn, "refresh token is empty")

		return
	}

	if err = c.storage.Set(ctx, clientID, refreshToken); err != nil {
		logger.LogAttrs(
			ctx, slog.LevelWarn, "unable to store refresh token",
			slog.Any("err", err),
		)
	}
}

// logRefreshTokenError logs missing refresh-token errors at a lower level for already authenticated sessions.
func (c *Client) logRefreshTokenError(ctx context.Context, logger *slog.Logger, oAuth2State state.State, err error) {
	logLevel := slog.LevelWarn

	if errors.Is(err, ErrNoRefreshToken) {
		if oAuth2State.SessionState == "AuthenticatedEmptyUser" || oAuth2State.SessionState == "Authenticated" {
			logLevel = slog.LevelDebug
		}
	}

	logger.LogAttrs(ctx, logLevel, fmt.Errorf("oauth2.refresh is enabled, but %w", err).Error())
}

// ClientDisconnect purges the refresh token from the [tokenstorage.Storage].
func (c *Client) ClientDisconnect(ctx context.Context, logger *slog.Logger, client connection.Client) {
	if c.conf.OAuth2.Refresh.UseSessionID {
		return
	}

	clientID := strconv.FormatUint(client.CID, 10)
	if c.conf.OAuth2.Refresh.UseSessionID && client.SessionID != "" {
		clientID = client.SessionID
	}

	refreshToken, err := c.storage.Get(ctx, clientID)
	if err != nil {
		logLevel := slog.LevelWarn
		if errors.Is(err, tokenstorage.ErrNotExists) {
			logLevel = slog.LevelDebug
		}

		logger.LogAttrs(ctx, logLevel, fmt.Errorf("error from token store: %w", err).Error())

		return
	}

	if err = c.storage.Delete(ctx, clientID); err != nil {
		logger.LogAttrs(ctx, slog.LevelWarn, fmt.Errorf("error delete refresh token from storage: %w", err).Error())

		return
	}

	if !c.conf.OAuth2.Refresh.ValidateUser {
		return
	}

	logger.LogAttrs(ctx, slog.LevelDebug, "revoke refresh token")

	if err = c.provider.RevokeRefreshToken(ctx, logger, c.relyingParty, refreshToken); err != nil {
		logger.LogAttrs(ctx, slog.LevelWarn, err.Error())
	}
}
