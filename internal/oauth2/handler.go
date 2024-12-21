package oauth2

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
	"github.com/zitadel/logging"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type openvpnManagementClient interface {
	AcceptClient(logger *slog.Logger, client state.ClientIdentifier, username string)
	DenyClient(logger *slog.Logger, client state.ClientIdentifier, reason string)
}

// OAuth2Start returns a http.Handler that starts the OAuth2 authorization flow.
// It checks if the request has a valid state GET parameter generated by state.New.
// Optionally, it checks the HTTP client IP address against the VPN IP address.
// After the checks, the request is delegated to [rp.AuthURLHandler].
func (c Client) OAuth2Start() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// check if request has a state GET parameter generated state.New.
		sessionState := r.URL.Query().Get("state")
		if sessionState == "" {
			w.WriteHeader(http.StatusBadRequest)

			return
		}

		// decode the state GET parameter
		session, err := state.NewWithEncodedToken(sessionState, c.conf.HTTP.Secret.String())
		if err != nil {
			c.logger.Warn(utils.StringConcat("invalid state: ", err.Error()))
			w.WriteHeader(http.StatusBadRequest)

			return
		}

		logger := c.logger.With(
			slog.String("ip", fmt.Sprintf("%s:%s", session.IPAddr, session.IPPort)),
			slog.Uint64("cid", session.Client.CID),
			slog.Uint64("kid", session.Client.KID),
			slog.String("common_name", session.CommonName),
		)

		if c.conf.HTTP.Check.IPAddr {
			if err := checkClientIPAddr(r, c.conf, session); err != nil {
				logger.LogAttrs(r.Context(), slog.LevelWarn, err.Error())

				if !errors.Is(err, ErrClientRejected) {
					c.openvpn.DenyClient(logger, session.Client, "client rejected")
					w.WriteHeader(http.StatusInternalServerError)

					return
				}

				c.openvpn.DenyClient(logger, session.Client, err.Error())
				w.WriteHeader(http.StatusForbidden)

				return
			}
		}

		logger.LogAttrs(r.Context(), slog.LevelInfo, "initialize authorization via oauth2")

		if c.conf.OAuth2.Nonce {
			id := strconv.FormatUint(session.Client.CID, 10)
			if c.conf.OAuth2.Refresh.UseSessionID && session.Client.SessionID != "" {
				id = session.Client.SessionID
			}

			c.authorizeParams = append(c.authorizeParams, rp.WithURLParam("nonce", c.getNonce(id)))
		}

		rp.AuthURLHandler(func() string {
			return sessionState
		}, c.relyingParty, c.authorizeParams...).ServeHTTP(w, r)
	})
}

// OAuth2Callback returns a http.Handler that handles the OAuth2 callback.
func (c Client) OAuth2Callback() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()

		encryptedState := r.URL.Query().Get("state")
		if encryptedState == "" {
			c.writeHTTPError(w, c.logger, http.StatusBadRequest, "Bad Request", "state is empty")

			return
		}

		session, err := state.NewWithEncodedToken(encryptedState, c.conf.HTTP.Secret.String())
		if err != nil {
			c.writeHTTPError(w, c.logger, http.StatusBadRequest, "Invalid State", err.Error())

			return
		}

		logger := c.logger.With(
			slog.String("ip", fmt.Sprintf("%s:%s", session.IPAddr, session.IPPort)),
			slog.Uint64("cid", session.Client.CID),
			slog.Uint64("kid", session.Client.KID),
			slog.String("common_name", session.CommonName),
			slog.String("session_id", session.Client.SessionID),
			slog.String("session_state", session.SessionState),
		)

		ctx = logging.ToContext(ctx, logger)

		clientID := strconv.FormatUint(session.Client.CID, 10)
		if c.conf.OAuth2.Refresh.UseSessionID && session.Client.SessionID != "" {
			clientID = session.Client.SessionID
		}

		if c.conf.OAuth2.Nonce {
			ctx = context.WithValue(ctx, types.CtxNonce{}, c.getNonce(clientID))
			r = r.WithContext(ctx)
		}

		rp.CodeExchangeHandler(
			c.postCodeExchangeHandler(logger, session, clientID),
			c.relyingParty,
		).ServeHTTP(w, r)
	})
}

func (c Client) postCodeExchangeHandler(logger *slog.Logger, session state.State, clientID string) rp.CodeExchangeCallback[*idtoken.Claims] {
	return func(
		w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*idtoken.Claims], _ string,
		_ rp.RelyingParty,
	) {
		ctx := r.Context()

		if tokens.IDTokenClaims != nil {
			logger = logger.With(
				slog.String("idtoken_subject", tokens.IDTokenClaims.Subject),
				slog.String("idtoken_email", tokens.IDTokenClaims.EMail),
				slog.String("idtoken_preferred_username", tokens.IDTokenClaims.PreferredUsername),
			)

			logger.Debug("claims", slog.Any("claims", tokens.IDTokenClaims.Claims))
		}

		user, err := c.provider.GetUser(ctx, logger, tokens)
		if err != nil {
			c.openvpn.DenyClient(logger, session.Client, "unable to fetch user data")
			c.writeHTTPError(w, logger, http.StatusInternalServerError, "fetchUser", err.Error())

			return
		}

		logger = logger.With(
			slog.String("user_subject", user.Subject),
			slog.String("user_preferred_username", user.PreferredUsername),
		)

		if err = c.provider.CheckUser(ctx, session, user, tokens); err != nil {
			c.openvpn.DenyClient(logger, session.Client, "client rejected")
			c.writeHTTPError(w, logger, http.StatusInternalServerError, "user validation", err.Error())

			return
		}

		logger.LogAttrs(ctx, slog.LevelInfo, "successful authorization via oauth2")

		c.openvpn.AcceptClient(logger, session.Client, session.CommonName)
		c.writeHTTPSuccess(w, logger)
		c.postCodeExchangeHandlerStoreRefreshToken(ctx, logger, session, clientID, tokens)
	}
}

func (c Client) postCodeExchangeHandlerStoreRefreshToken(ctx context.Context, logger *slog.Logger, session state.State, clientID string, tokens *oidc.Tokens[*idtoken.Claims]) {
	if !c.conf.OAuth2.Refresh.Enabled {
		return
	}

	if !c.conf.OAuth2.Refresh.ValidateUser {
		if err := c.storage.Set(clientID, types.EmptyToken); err != nil {
			logger.Warn(err.Error())
		}

		return
	}

	refreshToken, err := c.provider.GetRefreshToken(tokens)
	if err != nil {
		logLevel := slog.LevelWarn
		if errors.Is(err, ErrNoRefreshToken) {
			if session.SessionState == "AuthenticatedEmptyUser" || session.SessionState == "Authenticated" {
				logLevel = slog.LevelDebug
			}
		}

		logger.LogAttrs(ctx, logLevel, fmt.Errorf("oauth2.refresh is enabled, but %w", err).Error())
	}

	if refreshToken == "" {
		logger.LogAttrs(ctx, slog.LevelWarn, "refresh token is empty")
	} else if err = c.storage.Set(clientID, refreshToken); err != nil {
		logger.LogAttrs(ctx, slog.LevelWarn, "unable to store refresh token",
			slog.Any("err", err),
		)
	}
}

func (c Client) httpErrorHandler(w http.ResponseWriter, httpStatus int, errorType string, errorDesc string, encryptedSession string) {
	logger := c.logger

	session, err := state.NewWithEncodedToken(encryptedSession, c.conf.HTTP.Secret.String())
	if err == nil {
		logger = c.logger.With(
			slog.String("ip", fmt.Sprintf("%s:%s", session.IPAddr, session.IPPort)),
			slog.Uint64("cid", session.Client.CID),
			slog.Uint64("kid", session.Client.KID),
			slog.String("common_name", session.CommonName),
		)

		c.openvpn.DenyClient(logger, session.Client, "client rejected")
	} else {
		c.logger.Debug("httpErrorHandler: " + err.Error())
	}

	c.writeHTTPError(w, logger, httpStatus, errorType, errorDesc)
}

func (c Client) writeHTTPError(w http.ResponseWriter, logger *slog.Logger, httpCode int, errorType, errorDesc string) {
	if httpCode == http.StatusUnauthorized {
		httpCode = http.StatusForbidden
	}

	h := sha256.New()
	h.Write([]byte(time.Now().String()))

	errorID := hex.EncodeToString(h.Sum(nil))

	logger.Warn(fmt.Sprintf("%s: %s", errorType, errorDesc), slog.String("error_id", errorID))
	w.WriteHeader(httpCode)

	err := c.conf.HTTP.CallbackTemplate.Execute(w, map[string]string{
		"title":   "Access denied",
		"message": "Please contact your administrator.",
		"errorID": errorID,
	})
	if err != nil {
		logger.Error(fmt.Errorf("executing template: %w", err).Error())
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func (c Client) writeHTTPSuccess(w http.ResponseWriter, logger *slog.Logger) {
	err := c.conf.HTTP.CallbackTemplate.Execute(w, map[string]string{
		"title":   "Access granted",
		"message": "You can close this window now.",
		"errorID": "",
	})
	if err != nil {
		logger.Error(fmt.Errorf("executing template: %w", err).Error())
		w.WriteHeader(http.StatusInternalServerError)
	}
}
