package oauth2

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/zitadel/oidc/v2/pkg/client/rp"
	"github.com/zitadel/oidc/v2/pkg/oidc"
)

func Handler(logger *slog.Logger, oidcClient *rp.RelyingParty, conf *config.Config, openvpnClient *openvpn.Client) *http.ServeMux {
	baseUrl, _ := url.Parse(conf.Http.BaseUrl)

	mux := http.NewServeMux()
	mux.Handle("/", http.NotFoundHandler())
	mux.Handle(strings.TrimSuffix(baseUrl.Path, "/")+"/oauth2/start", oauth2Start(logger, oidcClient, conf))
	mux.Handle(strings.TrimSuffix(baseUrl.Path, "/")+"/oauth2/callback", oauth2Callback(logger, oidcClient, conf, openvpnClient))

	return mux
}

func oauth2Start(logger *slog.Logger, oidcClient *rp.RelyingParty, conf *config.Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessionState := r.URL.Query().Get("state")
		if sessionState == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		session := state.NewEncoded(sessionState)
		if err := session.Decode(conf.Http.Secret); err != nil {
			logger.Warn(fmt.Sprintf("invalid state: %s", sessionState))
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		logger.Info("initialize authorization via oauth2",
			"common_name", session.CommonName,
			"cid", session.Cid,
			"kid", session.Kid,
		)

		rp.AuthURLHandler(func() string {
			return sessionState
		}, *oidcClient).ServeHTTP(w, r)
	})
}

func oauth2Callback(logger *slog.Logger, oidcClient *rp.RelyingParty, conf *config.Config, openvpnClient *openvpn.Client) http.Handler {

	return rp.CodeExchangeHandler(func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], encryptedState string, rp rp.RelyingParty) {
		session := state.NewEncoded(encryptedState)
		if err := session.Decode(conf.Http.Secret); err != nil {
			logger.Warn(err.Error(),
				"subject", tokens.IDTokenClaims.Subject,
				"preferred_username", tokens.IDTokenClaims.PreferredUsername,
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if err := validateToken(conf, session, tokens); err != nil {
			logger.Warn(err.Error(),
				"subject", tokens.IDTokenClaims.Subject,
				"preferred_username", tokens.IDTokenClaims.PreferredUsername,
				"common_name", session.CommonName,
				"cid", session.Cid,
				"kid", session.Kid,
			)

			openvpnClient.SendCommand("client-deny %d %d \"%s\"", session.Cid, session.Kid, err.Error())

			if conf.Http.CallbackTemplate == nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			} else {
				err := conf.Http.CallbackTemplate.Execute(w, map[string]string{
					"errorDesc": err.Error(),
					"errorType": "tokenValidation",
				})

				if err != nil {
					logger.Error("executing template:", err)
					w.WriteHeader(http.StatusInternalServerError)
				}
			}

			return
		}

		logger.Info("successful authorization via oauth2",
			"subject", tokens.IDTokenClaims.Subject,
			"preferred_username", tokens.IDTokenClaims.PreferredUsername,
			"common_name", session.CommonName,
			"cid", session.Cid,
			"kid", session.Kid,
		)

		openvpnClient.SendCommand("client-auth-nt %d %d", session.Cid, session.Kid)

		if conf.Http.CallbackTemplate == nil {
			_, _ = w.Write([]byte(callbackHtml))
		} else if err := conf.Http.CallbackTemplate.Execute(w, map[string]string{}); err != nil {
			logger.Error("executing template:", err)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}, *oidcClient)
}
