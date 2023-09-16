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
	mux.Handle("/oauth2/start", oauth2Start(logger, oidcClient, conf))
	mux.Handle("/oauth2/callback", oauth2Callback(logger, oidcClient, conf, openvpnClient))

	return mux
}

func oauth2Start(logger *zap.SugaredLogger, oidcClient *rp.RelyingParty, conf *config.Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessionState := r.URL.Query().Get("state")
		if sessionState == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		session := state.NewEncoded(sessionState)
		if err := session.Decode(conf.Http.SessionSecret); err != nil {
			logger.Warnf("invalid state: %s", sessionState)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		logger.Infow("initialize authorization via oauth2",
			"common_name", session.CommonName,
			"cid", session.Cid,
			"kid", session.Kid,
		)

		rp.AuthURLHandler(func() string {
			return sessionState
		}, *oidcClient).ServeHTTP(w, r)
	})
}

func oauth2Callback(
	logger *zap.SugaredLogger, oidcClient *rp.RelyingParty, conf *config.Config, openvpnClient *openvpn.Client) http.Handler {

	return rp.CodeExchangeHandler(func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], encryptedState string, rp rp.RelyingParty) {
		session := state.NewEncoded(encryptedState)
		if err := session.Decode(conf.Http.SessionSecret); err != nil {
			logger.Warnw(err.Error(),
				"subject", tokens.IDTokenClaims.Subject,
				"preferred_username", tokens.IDTokenClaims.PreferredUsername,
			)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if err := validateToken(conf, session, tokens); err != nil {
			logger.Warnw(err.Error(),
				"subject", tokens.IDTokenClaims.Subject,
				"preferred_username", tokens.IDTokenClaims.PreferredUsername,
				"common_name", session.CommonName,
				"cid", session.Cid,
				"kid", session.Kid,
			)

			openvpnClient.SendCommand("client-deny %d %d \"%s\"", session.Cid, session.Kid, err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		logger.Infow("successful authorization via oauth2",
			"subject", tokens.IDTokenClaims.Subject,
			"preferred_username", tokens.IDTokenClaims.PreferredUsername,
			"common_name", session.CommonName,
			"cid", session.Cid,
			"kid", session.Kid,
		)

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
