package oauth2

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/ui"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type OpenVPN interface {
	AcceptClient(logger *slog.Logger, client state.ClientIdentifier, username string)
	DenyClient(logger *slog.Logger, client state.ClientIdentifier, reason string)
}

func (p *Provider) Handler() *http.ServeMux {
	staticFs, err := fs.Sub(ui.Static, "static")
	if err != nil {
		panic(err)
	}

	basePath := strings.TrimSuffix(p.conf.HTTP.BaseURL.Path, "/")

	mux := http.NewServeMux()
	mux.Handle("/", http.NotFoundHandler())
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFs))))
	mux.Handle(utils.StringConcat(basePath, "/oauth2/start"), p.oauth2Start())
	mux.Handle(utils.StringConcat(basePath, "/oauth2/callback"), p.oauth2Callback())

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

		session := state.NewEncoded(sessionState)
		if err := session.Decode(p.conf.HTTP.Secret.String()); err != nil {
			p.logger.Warn(utils.StringConcat("invalid state: ", err.Error()))
			p.logger.Debug(sessionState)
			w.WriteHeader(http.StatusBadRequest)

			return
		}

		logger := p.logger.With(
			slog.String("common_name", session.CommonName),
			slog.Uint64("cid", session.Client.Cid),
			slog.Uint64("kid", session.Client.Kid),
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

		rp.AuthURLHandler(func() string {
			return sessionState
		}, p.RelyingParty, p.authorizeParams...).ServeHTTP(w, r)
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

	if clientIP != session.Ipaddr {
		reason := utils.StringConcat("http client ip ", clientIP, " and vpn ip ", session.Ipaddr, " is different.")
		logger.Warn(reason)

		return false, http.StatusForbidden, reason
	}

	return true, 0, ""
}

func (p *Provider) oauth2Callback() http.Handler {
	return rp.CodeExchangeHandler(func(
		w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*idtoken.Claims], encryptedSession string,
		rp rp.RelyingParty,
	) {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		logger := p.logger
		if tokens.IDTokenClaims != nil {
			logger = logger.With(
				slog.String("idtoken.subject", tokens.IDTokenClaims.Subject),
				slog.String("idtoken.preferred_username", tokens.IDTokenClaims.PreferredUsername),
			)
		}

		session := state.NewEncoded(encryptedSession)
		if err := session.Decode(p.conf.HTTP.Secret.String()); err != nil {
			logger.Warn(err.Error())
			logger.Debug(encryptedSession)
			writeError(w, logger, p.conf, http.StatusInternalServerError, "invalidSession", err.Error())

			return
		}

		logger = logger.With(
			slog.String("common_name", session.CommonName),
			slog.Uint64("cid", session.Client.Cid),
			slog.Uint64("kid", session.Client.Kid),
		)

		user, err := p.OIDC.GetUser(ctx, tokens)
		if err != nil {
			logger.Error(err.Error())
			p.openvpn.DenyClient(logger, session.Client, "unable to fetch user data")
			writeError(w, logger, p.conf, http.StatusInternalServerError, "fetchUser", err.Error())

			return
		}

		logger = logger.With(
			slog.String("user.subject", user.Subject),
			slog.String("user.preferred_username", user.PreferredUsername),
		)

		err = p.OIDC.CheckUser(ctx, session, user, tokens)
		if err != nil {
			reason := err.Error()
			logger.Warn(reason)
			p.openvpn.DenyClient(logger, session.Client, "client rejected")

			writeError(w, logger, p.conf, http.StatusInternalServerError, "tokenValidation", reason)

			return
		}

		logger.Info("successful authorization via oauth2")

		p.openvpn.AcceptClient(logger, session.Client, getAuthTokenUsername(session, user))

		if p.conf.OAuth2.Refresh.Enabled {
			if tokens.RefreshToken == "" {
				p.logger.Warn("oauth2.refresh is enabled, but provider does not return refresh token")
			} else if err = p.storage.Set(session.Client.Cid, tokens.RefreshToken); err != nil {
				logger.Warn(err.Error())
			}
		}

		writeSuccess(w, p.conf, logger)
	}, p.RelyingParty)
}

func getAuthTokenUsername(session state.State, user types.UserData) string {
	username := session.CommonName
	if user.PreferredUsername != "" {
		username = user.PreferredUsername
	} else if user.Subject != "" {
		username = user.Subject
	}

	return username
}

func writeError(w http.ResponseWriter, logger *slog.Logger, conf config.Config, httpCode int, errorType, errorDesc string) {
	err := conf.HTTP.CallbackTemplate.Execute(w, map[string]string{
		"title":   errorType,
		"message": errorDesc,
	})
	if err != nil {
		logger.Error("executing template:", err)
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	w.WriteHeader(httpCode)
}

func writeSuccess(w http.ResponseWriter, conf config.Config, logger *slog.Logger) {
	err := conf.HTTP.CallbackTemplate.Execute(w, map[string]string{
		"title":   "You have logged into OpenVPN!",
		"message": "You can close this window now.",
	})
	if err != nil {
		logger.Error(fmt.Sprintf("executing template: %s", err))
		w.WriteHeader(http.StatusInternalServerError)
	}
}
