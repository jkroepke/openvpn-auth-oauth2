package oauth2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/openvpn/connection"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/tokenstorage"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
)

const (
	internalRefreshTokenPrefix = types.EmptyToken + "client-config:"
	providerRefreshTokenPrefix = types.EmptyToken + "refresh-token:"
)

type internalRefreshToken struct {
	ClientConfigNames []string `json:"client-config-names,omitempty"`
}

type providerRefreshToken struct {
	RefreshToken      string   `json:"refresh-token"`
	ClientConfigNames []string `json:"client-config-names,omitempty"`
}

// RefreshClientAuth initiates non-interactive authentication against the SSO provider.
func (c *Client) RefreshClientAuth(
	ctx context.Context, logger *slog.Logger, client connection.Client,
) (types.UserInfo, *idtoken.IDToken, []string, bool, error) {
	clientID := c.getRefreshClientID(client)

	refreshToken, hasRefreshToken, err := c.loadRefreshToken(ctx, logger, clientID)
	if err != nil {
		return types.UserInfo{}, nil, nil, false, err
	}

	if !hasRefreshToken {
		return types.UserInfo{}, nil, nil, false, nil
	}

	if !c.conf.OAuth2.Refresh.ValidateUser {
		clientConfigNames, err := decodeInternalRefreshToken(refreshToken)
		if err != nil {
			return types.UserInfo{}, nil, nil, false, err
		}

		logger.LogAttrs(ctx, slog.LevelInfo, "successful non-interactive authentication via internal token")

		return types.UserInfo{}, nil, clientConfigNames, true, nil
	}

	refreshToken, clientConfigNames, err := decodeProviderRefreshToken(refreshToken)
	if err != nil {
		return types.UserInfo{}, nil, nil, false, err
	}

	ctx = c.withRefreshNonce(ctx, clientID)

	tokens, err := c.refreshTokens(ctx, logger, refreshToken)
	if err != nil {
		return types.UserInfo{}, nil, nil, false, err
	}

	oAuth2State := refreshOAuth2State(client)

	user, err := c.validateRefreshedUser(ctx, logger, oAuth2State, tokens)
	if err != nil {
		return types.UserInfo{}, nil, nil, false, err
	}

	logger.LogAttrs(ctx, slog.LevelInfo, "successful authenticate via refresh token")

	c.storeRotatedRefreshToken(ctx, logger, oAuth2State, clientID, tokens, clientConfigNames)

	return user, tokens, clientConfigNames, true, nil
}

func encodeInternalRefreshToken(clientConfigNames []string) (string, error) {
	if len(clientConfigNames) == 0 {
		return types.EmptyToken, nil
	}

	tokenBytes, err := json.Marshal(internalRefreshToken{ClientConfigNames: clientConfigNames})
	if err != nil {
		return "", fmt.Errorf("unable to marshal internal refresh token: %w", err)
	}

	return internalRefreshTokenPrefix + string(tokenBytes), nil
}

func decodeInternalRefreshToken(refreshToken string) ([]string, error) {
	if !strings.HasPrefix(refreshToken, internalRefreshTokenPrefix) {
		return nil, nil
	}

	var token internalRefreshToken
	if err := json.Unmarshal([]byte(strings.TrimPrefix(refreshToken, internalRefreshTokenPrefix)), &token); err != nil {
		return nil, fmt.Errorf("unable to parse internal refresh token: %w", err)
	}

	return validateClientConfigNames(token.ClientConfigNames)
}

func encodeProviderRefreshToken(refreshToken string, clientConfigNames []string) (string, error) {
	if len(clientConfigNames) == 0 {
		return refreshToken, nil
	}

	tokenBytes, err := json.Marshal(providerRefreshToken{
		RefreshToken:      refreshToken,
		ClientConfigNames: clientConfigNames,
	})
	if err != nil {
		return "", fmt.Errorf("unable to marshal provider refresh token: %w", err)
	}

	return providerRefreshTokenPrefix + string(tokenBytes), nil
}

func decodeProviderRefreshToken(refreshToken string) (string, []string, error) {
	if !strings.HasPrefix(refreshToken, providerRefreshTokenPrefix) {
		return refreshToken, nil, nil
	}

	var token providerRefreshToken
	if err := json.Unmarshal([]byte(strings.TrimPrefix(refreshToken, providerRefreshTokenPrefix)), &token); err != nil {
		return "", nil, fmt.Errorf("unable to parse provider refresh token: %w", err)
	}

	if token.RefreshToken == "" {
		return "", nil, errors.New("provider refresh token is empty")
	}

	clientConfigNames, err := validateClientConfigNames(token.ClientConfigNames)
	if err != nil {
		return "", nil, err
	}

	return token.RefreshToken, clientConfigNames, nil
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
	clientConfigNames []string,
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

	refreshToken, err = encodeProviderRefreshToken(refreshToken, clientConfigNames)
	if err != nil {
		logger.LogAttrs(ctx, slog.LevelWarn, err.Error())

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
	if !c.conf.OAuth2.Refresh.Enabled || c.conf.OAuth2.Refresh.UseSessionID {
		return
	}

	clientID := strconv.FormatUint(client.CID, 10)

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

	refreshToken, _, err = decodeProviderRefreshToken(refreshToken)
	if err != nil {
		logger.LogAttrs(ctx, slog.LevelWarn, err.Error())

		return
	}

	logger.LogAttrs(ctx, slog.LevelDebug, "revoke refresh token")

	if err = c.provider.RevokeRefreshToken(ctx, logger, c.relyingParty, refreshToken); err != nil {
		logger.LogAttrs(ctx, slog.LevelWarn, err.Error())
	}
}
