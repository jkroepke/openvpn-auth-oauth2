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
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
	"github.com/zitadel/oidc/v2/pkg/client/rp"
	"github.com/zitadel/oidc/v2/pkg/oidc"
)

func Handler(logger *slog.Logger, provider Provider, conf config.Config, openvpnClient *openvpn.Client) *http.ServeMux {
	basePath := strings.TrimSuffix(conf.HTTP.BaseURL.Path, "/")

	mux := http.NewServeMux()
	mux.Handle("/", http.NotFoundHandler())
	mux.Handle(utils.StringConcat(basePath, "/oauth2/start"), oauth2Start(logger, provider, conf, openvpnClient))
	mux.Handle(utils.StringConcat(basePath, "/oauth2/callback"), oauth2Callback(logger, provider, conf, openvpnClient))

	return mux
}

func oauth2Start(logger *slog.Logger, provider Provider, conf config.Config, openvpnClient *openvpn.Client) http.Handler {
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
			slog.Uint64("cid", session.Cid),
			slog.Uint64("kid", session.Kid),
		)

		if conf.HTTP.Check.IPAddr {
			ok, httpStatusCode := checkClientIPAddr(r, logger, session, openvpnClient, conf)
			if !ok {
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

func checkClientIPAddr(
	r *http.Request, logger *slog.Logger, session state.State, openvpnClient *openvpn.Client, conf config.Config,
) (bool, int) {
	clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		logger.Warn(err.Error())

		_, err := openvpnClient.SendCommandf(`client-deny %d %d "%s"`, session.Cid, session.Kid, "client rejected")
		if err != nil {
			logger.Warn(err.Error())
		}

		return false, http.StatusInternalServerError
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

		_, err := openvpnClient.SendCommandf(`client-deny %d %d "%s"`, session.Cid, session.Kid, reason)
		if err != nil {
			logger.Warn(err.Error())
		}

		return false, http.StatusForbidden
	}

	return true, 0
}

func oauth2Callback(
	logger *slog.Logger, provider Provider, conf config.Config, openvpnClient *openvpn.Client,
) http.Handler {
	return rp.CodeExchangeHandler(func(
		w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], sessionState string,
		rp rp.RelyingParty,
	) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		logger = logger.With(
			slog.String("subject", tokens.IDTokenClaims.Subject),
			slog.String("preferred_username", tokens.IDTokenClaims.PreferredUsername),
		)

		session := state.NewEncoded(sessionState)
		if err := session.Decode(conf.HTTP.Secret); err != nil {
			logger.Warn(err.Error())
			logger.Debug(sessionState)
			writeError(w, logger, conf, http.StatusInternalServerError, "invalidSession", err.Error())

			return
		}

		logger = logger.With(
			slog.String("common_name", session.CommonName),
			slog.Uint64("cid", session.Cid),
			slog.Uint64("kid", session.Kid),
		)

		user, err := provider.OIDC.GetUser(ctx, tokens)
		if err != nil {
			logger.Error(err.Error())

			_, err = openvpnClient.SendCommandf(`client-deny %d %d "%s"`, session.Cid, session.Kid, "unable to fetch user data")
			if err != nil {
				logger.Warn(err.Error())
			}

			writeError(w, logger, conf, http.StatusInternalServerError, "fetchUser", err.Error())

			return
		}

		err = provider.OIDC.CheckUser(ctx, session, user, tokens)
		if err != nil {
			reason := err.Error()
			logger.Warn(reason)

			_, err = openvpnClient.SendCommandf(`client-deny %d %d "%s"`, session.Cid, session.Kid, "client rejected")
			if err != nil {
				logger.Warn(err.Error())
			}

			writeError(w, logger, conf, http.StatusInternalServerError, "tokenValidation", reason)

			return
		}

		logger.Info("successful authorization via oauth2")

		if conf.OpenVpn.AuthTokenUser {
			username := getAuthTokenUsername(session, user)
			_, err = openvpnClient.SendCommandf("client-auth %d %d\npush \"auth-token-user %s\"\nEND", session.Cid, session.Kid, username)
		} else {
			_, err = openvpnClient.SendCommandf("client-auth-nt %d %d", session.Cid, session.Kid)
		}

		if err != nil {
			logger.Warn(err.Error())
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
