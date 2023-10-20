package oauth2

import (
	"context"
	"encoding/base64"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type OpenVPN interface {
	AcceptClient(logger *slog.Logger, client state.ClientIdentifier)
	AcceptClientWithToken(logger *slog.Logger, client state.ClientIdentifier, username string)
	DenyClient(logger *slog.Logger, client state.ClientIdentifier, reason string)
}

func Handler(logger *slog.Logger, conf config.Config, provider Provider, openvpnCallback OpenVPN) *http.ServeMux {
	basePath := strings.TrimSuffix(conf.HTTP.BaseURL.Path, "/")

	mux := http.NewServeMux()
	mux.Handle("/", http.NotFoundHandler())
	mux.Handle(utils.StringConcat(basePath, "/oauth2/start"), oauth2Start(logger, provider, conf, openvpnCallback))
	mux.Handle(utils.StringConcat(basePath, "/oauth2/callback"), oauth2Callback(logger, provider, conf, openvpnCallback))

	return mux
}

func oauth2Start(logger *slog.Logger, provider Provider, conf config.Config, openvpn OpenVPN) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessionState := r.URL.Query().Get("state")
		if sessionState == "" {
			w.WriteHeader(http.StatusBadRequest)

			return
		}

		session := state.NewEncoded(sessionState)
		if err := session.Decode(conf.HTTP.Secret); err != nil {
			logger.Warn(utils.StringConcat("invalid state: ", err.Error()))
			logger.Debug(sessionState)
			w.WriteHeader(http.StatusBadRequest)

			return
		}

		logger = logger.With(
			slog.String("common_name", session.CommonName),
			slog.Uint64("cid", session.Client.Cid),
			slog.Uint64("kid", session.Client.Kid),
		)

		if conf.HTTP.Check.IPAddr {
			ok, httpStatusCode, denyReason := checkClientIPAddr(r, logger, session, conf)
			if !ok {
				openvpn.DenyClient(logger, session.Client, denyReason)
				w.WriteHeader(httpStatusCode)

				return
			}
		}

		logger.Info("initialize authorization via oauth2")

		rp.AuthURLHandler(func() string {
			return sessionState
		}, provider.RelyingParty).ServeHTTP(w, r)
	})
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

func oauth2Callback(
	logger *slog.Logger, provider Provider, conf config.Config, openvpn OpenVPN,
) http.Handler {
	return rp.CodeExchangeHandler(func(
		w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], encryptedSession string,
		rp rp.RelyingParty,
	) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		logger = logger.With(
			slog.String("subject", tokens.IDTokenClaims.Subject),
			slog.String("preferred_username", tokens.IDTokenClaims.PreferredUsername),
		)

		session := state.NewEncoded(encryptedSession)
		if err := session.Decode(conf.HTTP.Secret); err != nil {
			logger.Warn(err.Error())
			logger.Debug(encryptedSession)
			writeError(w, logger, conf, http.StatusInternalServerError, "invalidSession", err.Error())

			return
		}

		logger = logger.With(
			slog.String("common_name", session.CommonName),
			slog.Uint64("cid", session.Client.Cid),
			slog.Uint64("kid", session.Client.Kid),
		)

		user, err := provider.OIDC.GetUser(ctx, tokens)
		if err != nil {
			logger.Error(err.Error())
			openvpn.DenyClient(logger, session.Client, "unable to fetch user data")
			writeError(w, logger, conf, http.StatusInternalServerError, "fetchUser", err.Error())

			return
		}

		err = provider.OIDC.CheckUser(ctx, session, user, tokens)
		if err != nil {
			reason := err.Error()
			logger.Warn(reason)
			openvpn.DenyClient(logger, session.Client, "client rejected")

			writeError(w, logger, conf, http.StatusInternalServerError, "tokenValidation", reason)

			return
		}

		logger.Info("successful authorization via oauth2")

		if conf.OpenVpn.AuthTokenUser {
			username := getAuthTokenUsername(session, user)
			openvpn.AcceptClientWithToken(logger, session.Client, username)
		} else {
			openvpn.AcceptClient(logger, session.Client)
		}

		writeSuccess(w, conf, logger)
	}, provider.RelyingParty)
}

func getAuthTokenUsername(session state.State, user types.UserData) string {
	username := session.CommonName
	if user.PreferredUsername != "" {
		username = user.PreferredUsername
	} else if user.Subject != "" {
		username = user.Subject
	}

	return base64.StdEncoding.EncodeToString([]byte(username))
}

func writeError(w http.ResponseWriter, logger *slog.Logger, conf config.Config, httpCode int, errorType, errorDesc string) {
	if conf.HTTP.CallbackTemplate == nil || conf.HTTP.CallbackTemplate.Tree == nil {
		http.Error(w, utils.StringConcat(errorType, ": ", errorDesc), httpCode)

		return
	}

	err := conf.HTTP.CallbackTemplate.Execute(w, map[string]string{
		"errorDesc": errorDesc,
		"errorType": errorType,
	})
	if err != nil {
		logger.Error("executing template:", err)
		w.WriteHeader(http.StatusInternalServerError)

		return
	}

	w.WriteHeader(httpCode)
}

func writeSuccess(w http.ResponseWriter, conf config.Config, logger *slog.Logger) {
	if conf.HTTP.CallbackTemplate == nil || conf.HTTP.CallbackTemplate.Tree == nil {
		_, _ = w.Write([]byte(callbackHTML))

		return
	}

	err := conf.HTTP.CallbackTemplate.Execute(w, map[string]string{})
	if err != nil {
		logger.Error("executing template:", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}
