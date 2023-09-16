package oauth2

import (
	"net/http"
	"strings"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/encrypt"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn"
	"github.com/zitadel/oidc/v2/pkg/client/rp"
	"github.com/zitadel/oidc/v2/pkg/oidc"
	"go.uber.org/zap"
)

func Handler(logger *zap.SugaredLogger, oidcClient *rp.RelyingParty, conf *config.Config, openvpnClient *openvpn.Client) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/oauth2/start", oauth2Start(logger, oidcClient))
	mux.Handle("/oauth2/callback", oauth2Callback(logger, oidcClient, conf, openvpnClient))

	return mux
}

func oauth2Start(logger *zap.SugaredLogger, oidcClient *rp.RelyingParty) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state := r.URL.Query().Get("state")
		if state == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		logger.Info(state)

		rp.AuthURLHandler(func() string {
			return state
		}, *oidcClient).ServeHTTP(w, r)
	})
}

func oauth2Callback(
	logger *zap.SugaredLogger, oidcClient *rp.RelyingParty, conf *config.Config, openvpnClient *openvpn.Client) http.Handler {

	return rp.CodeExchangeHandler(func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], encryptedState string, rp rp.RelyingParty) {
		logger.Info(encryptedState)
		state, err := encrypt.Decrypt(encryptedState, conf.Http.SessionSecret)

		if err != nil {
			logger.Warnf("Invalid state: %v", err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		ids := strings.Split(state, "|")

		openvpnClient.SendCommand("client-auth-nt %s %s", ids[0], ids[1])

		/*

		   		logger.Info(tokens.AccessToken)
		   		logger.Info(tokens.IDToken)
		   		logger.Info(tokens.RefreshToken)

		   		if tokens.RefreshToken != "" {
		               var tokenUsername string
		               if tokens.IDTokenClaims.PreferredUsername != "" {
		                   tokenUsername = tokens.IDTokenClaims.PreferredUsername
		               } else if tokens.IDTokenClaims.Email != "" {
		                   tokenUsername = tokens.IDTokenClaims.Email
		               } else {
		                   tokenUsername = tokens.IDTokenClaims.Subject
		               }

		               username := base64.StdEncoding.EncodeToString([]byte(tokenUsername))

		   			openvpnClient.SendCommand("client-auth %s %s\npush \"auth-token-user %s\"\npush \"auth-token %s\"\nEND", ids[0], ids[1], username, tokens.RefreshToken)
		   		}
		*/
		_, _ = w.Write([]byte(callbackHtml))
	}, *oidcClient)
}
