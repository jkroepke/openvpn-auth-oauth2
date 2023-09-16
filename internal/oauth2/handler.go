package oauth2

import (
	"net/http"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
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

		rp.AuthURLHandler(func() string {
			return state
		}, *oidcClient).ServeHTTP(w, r)
	})
}

func oauth2Callback(
	logger *zap.SugaredLogger, oidcClient *rp.RelyingParty, conf *config.Config, openvpnClient *openvpn.Client) http.Handler {

	return rp.CodeExchangeHandler(func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], encryptedState string, rp rp.RelyingParty) {
		session := state.NewEncoded(encryptedState)
		if err := session.Decode(conf.Http.SessionSecret); err != nil {
			logger.Warnf(err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if err := validateToken(conf, session, tokens); err != nil {
			logger.Warnw(err.Error(),
				"cid", session.Cid,
				"kid", session.Kid,
			)

			openvpnClient.SendCommand("client-deny %d %d \"%s\"", session.Cid, session.Kid, err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		openvpnClient.SendCommand("client-auth-nt %d %d", session.Cid, session.Kid)

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
