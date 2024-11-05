package oauth2

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/ui"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
	"github.com/zitadel/logging"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type OpenVPN interface {
	AcceptClient(logger *slog.Logger, client state.ClientIdentifier, username string)
	DenyClient(logger *slog.Logger, client state.ClientIdentifier, reason string)
}

func (p *Provider) Handler() *http.ServeMux {
	staticFs, err := fs.Sub(ui.Static, "assets")
	if err != nil {
		panic(err)
	}

	if p.conf.HTTP.AssetPath != "" {
		staticFs = utils.NewOverlayFS(staticFs, os.DirFS(p.conf.HTTP.AssetPath))
	}

	basePath := strings.TrimSuffix(p.conf.HTTP.BaseURL.Path, "/")

	mux := http.NewServeMux()
	mux.Handle("/", http.NotFoundHandler())
	mux.Handle(fmt.Sprintf("GET %s/ready", basePath), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	mux.Handle(fmt.Sprintf("GET %s/assets/", basePath), http.StripPrefix(utils.StringConcat(basePath, "/assets/"), http.FileServerFS(staticFs)))
	mux.Handle(fmt.Sprintf("GET %s/oauth2/start", basePath), p.oauth2Start())
	mux.Handle(fmt.Sprintf("GET %s/oauth2/callback", basePath), p.oauth2Callback())

	return mux
}

func (p *Provider) oauth2Start() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sendCacheHeaders(w)

		sessionState := r.URL.Query().Get("state")
		if sessionState == "" {
			w.WriteHeader(http.StatusBadRequest)

			return
		}

		session, err := state.NewWithEncodedToken(sessionState, p.conf.HTTP.Secret.String())
		if err != nil {
			p.logger.Warn(utils.StringConcat("invalid state: ", err.Error()))
			w.WriteHeader(http.StatusBadRequest)

			return
		}

		logger := p.logger.With(
			slog.String("ip", fmt.Sprintf("%s:%s", session.IPAddr, session.IPPort)),
			slog.Uint64("cid", session.Client.CID),
			slog.Uint64("kid", session.Client.KID),
			slog.String("common_name", session.CommonName),
		)

		if p.conf.HTTP.Check.IPAddr {
			ok, httpStatusCode, denyReason := checkClientIPAddr(r, logger, session, p.conf)
			if !ok {
				p.openvpn.DenyClient(logger, session.Client, denyReason)
				w.WriteHeader(httpStatusCode)

				return
			}
		}

		logger.Info("initialize authorization via oauth2")

		authorizeParams := p.authorizeParams

		if p.conf.OAuth2.Nonce {
			id := strconv.FormatUint(session.Client.CID, 10)
			if p.conf.OAuth2.Refresh.UseSessionID && session.Client.SessionID != "" {
				id = session.Client.SessionID
			}

			authorizeParams = append(authorizeParams, rp.WithURLParam("nonce", p.GetNonce(id)))
		}

		rp.AuthURLHandler(func() string {
			return sessionState
		}, p.RelyingParty, authorizeParams...).ServeHTTP(w, r)
	})
}

func sendCacheHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
}

func checkClientIPAddr(r *http.Request, logger *slog.Logger, session state.State, conf config.Config) (bool, int, string) {
	clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		logger.Warn(err.Error())

		return false, http.StatusInternalServerError, "client rejected"
	}

	if strings.HasPrefix(r.RemoteAddr, "[") {
		clientIP = utils.StringConcat("[", clientIP, "]")
	}

	if conf.HTTP.EnableProxyHeaders {
		if fwdAddress := r.Header.Get("X-Forwarded-For"); fwdAddress != "" {
			clientIP = strings.Split(fwdAddress, ", ")[0]
		}
	}

	if clientIP != session.IPAddr {
		reason := utils.StringConcat("http client ip ", clientIP, " and vpn ip ", session.IPAddr, " is different.")
		logger.Warn(reason)

		return false, http.StatusForbidden, reason
	}

	return true, 0, ""
}

func (p *Provider) oauth2Callback() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sendCacheHeaders(w)

		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()

		encryptedState := r.URL.Query().Get("state")
		if encryptedState == "" {
			writeError(w, p.logger, p.conf, http.StatusBadRequest, "Bad Request", "state is empty")

			return
		}

		session, err := state.NewWithEncodedToken(encryptedState, p.conf.HTTP.Secret.String())
		if err != nil {
			writeError(w, p.logger, p.conf, http.StatusBadRequest, "Invalid State", err.Error())

			return
		}

		logger := p.logger.With(
			slog.String("ip", fmt.Sprintf("%s:%s", session.IPAddr, session.IPPort)),
			slog.Uint64("cid", session.Client.CID),
			slog.Uint64("kid", session.Client.KID),
			slog.String("session_id", session.Client.SessionID),
			slog.String("common_name", session.CommonName),
		)

		ctx = logging.ToContext(ctx, logger)

		clientID := strconv.FormatUint(session.Client.CID, 10)
		if p.conf.OAuth2.Refresh.UseSessionID && session.Client.SessionID != "" {
			clientID = session.Client.SessionID
		}

		if p.conf.OAuth2.Nonce {
			ctx = context.WithValue(ctx, types.CtxNonce{}, p.GetNonce(clientID))
			r = r.WithContext(ctx)
		}

		rp.CodeExchangeHandler(
			p.postCodeExchangeHandler(logger, session, clientID),
			p.RelyingParty,
		).ServeHTTP(w, r)
	})
}

func (p *Provider) postCodeExchangeHandler(
	logger *slog.Logger, session state.State, clientID string,
) rp.CodeExchangeCallback[*idtoken.Claims] {
	return func(
		w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*idtoken.Claims], _ string,
		_ rp.RelyingParty,
	) {
		if tokens.IDTokenClaims != nil {
			logger = logger.With(
				slog.String("idtoken_subject", tokens.IDTokenClaims.Subject),
				slog.String("idtoken_email", tokens.IDTokenClaims.EMail),
				slog.String("idtoken_preferred_username", tokens.IDTokenClaims.PreferredUsername),
			)

			logger.Debug("claims", slog.Any("claims", tokens.IDTokenClaims.Claims))
		}

		user, err := p.Provider.GetUser(r.Context(), logger, tokens)
		if err != nil {
			p.openvpn.DenyClient(logger, session.Client, "unable to fetch user data")
			writeError(w, logger, p.conf, http.StatusInternalServerError, "fetchUser", err.Error())

			return
		}

		logger = logger.With(
			slog.String("user_subject", user.Subject),
			slog.String("user_preferred_username", user.PreferredUsername),
		)

		if err = p.Provider.CheckUser(r.Context(), session, user, tokens); err != nil {
			p.openvpn.DenyClient(logger, session.Client, "client rejected")
			writeError(w, logger, p.conf, http.StatusInternalServerError, "user validation", err.Error())

			return
		}

		logger.Info("successful authorization via oauth2")

		p.openvpn.AcceptClient(logger, session.Client, session.CommonName)

		if !p.conf.OAuth2.Refresh.Enabled {
			writeSuccess(w, p.conf, logger)

			return
		}

		if !p.conf.OAuth2.Refresh.ValidateUser {
			writeSuccess(w, p.conf, logger)

			if err = p.storage.Set(clientID, types.EmptyToken); err != nil {
				logger.Warn(err.Error())
			}

			return
		}

		refreshToken, err := p.Provider.GetRefreshToken(tokens)
		if err != nil {
			logger.Warn(fmt.Errorf("oauth2.refresh is enabled, but %w", err).Error())
		}

		if refreshToken == "" {
			logger.Warn("refresh token is empty")
		} else if err = p.storage.Set(clientID, refreshToken); err != nil {
			logger.Warn("unable to store refresh token",
				slog.Any("err", err),
			)
		}

		writeSuccess(w, p.conf, logger)
	}
}

func writeError(w http.ResponseWriter, logger *slog.Logger, conf config.Config, httpCode int, errorType, errorDesc string) {
	if httpCode == http.StatusUnauthorized {
		httpCode = http.StatusForbidden
	}

	h := sha256.New()
	h.Write([]byte(time.Now().String()))

	errorID := hex.EncodeToString(h.Sum(nil))

	logger.Warn(fmt.Sprintf("%s: %s", errorType, errorDesc), slog.String("error_id", errorID))
	w.WriteHeader(httpCode)

	err := conf.HTTP.CallbackTemplate.Execute(w, map[string]string{
		"title":   "Access denied",
		"message": "Please contact your administrator.",
		"errorID": errorID,
	})
	if err != nil {
		logger.Error(fmt.Errorf("executing template: %w", err).Error())
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func writeSuccess(w http.ResponseWriter, conf config.Config, logger *slog.Logger) {
	err := conf.HTTP.CallbackTemplate.Execute(w, map[string]string{
		"title":   "Access granted",
		"message": "You can close this window now.",
		"errorID": "",
	})
	if err != nil {
		logger.Error(fmt.Errorf("executing template: %w", err).Error())
		w.WriteHeader(http.StatusInternalServerError)
	}
}
