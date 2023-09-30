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
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
	"github.com/zitadel/oidc/v2/pkg/client/rp"
	"github.com/zitadel/oidc/v2/pkg/oidc"
)

func Handler(logger *slog.Logger, oidcProvider *Provider, conf config.Config, openvpnClient *openvpn.Client) *http.ServeMux {
	basePath := strings.TrimSuffix(conf.Http.BaseUrl.Path, "/")

	mux := http.NewServeMux()
	mux.Handle("/", http.NotFoundHandler())
	mux.Handle(utils.StringConcat(basePath, "/oauth2/start"), oauth2Start(logger, oidcProvider, conf, openvpnClient))
	mux.Handle(utils.StringConcat(basePath, "/oauth2/callback"), oauth2Callback(logger, oidcProvider, conf, openvpnClient))

	return mux
}

func oauth2Start(logger *slog.Logger, oidcProvider *Provider, conf config.Config, openvpnClient *openvpn.Client) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessionState := r.URL.Query().Get("state")
		if sessionState == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		session := state.NewEncoded(sessionState)
		if err := session.Decode(conf.Http.Secret); err != nil {
			logger.Warn(utils.StringConcat("invalid state: ", err.Error()))
			logger.Debug(sessionState)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if conf.Http.Check.IpAddr {
			clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
			if strings.HasPrefix(r.RemoteAddr, "[") {
				clientIP = utils.StringConcat("[", clientIP, "]")
			}

			if err != nil {
				logger.Warn(err.Error(),
					"common_name", session.CommonName,
					"cid", session.Cid,
					"kid", session.Kid,
				)

				openvpnClient.SendCommandf(`client-deny %d %d "%s"`, session.Cid, session.Kid, "client rejected")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			if conf.Http.EnableProxyHeaders {
				if fwdAddress := r.Header.Get("X-Forwarded-For"); fwdAddress != "" {
					clientIP = strings.Split(fwdAddress, ", ")[0]
				}
			}

			if clientIP != session.Ipaddr {
				logger.Warn(utils.StringConcat("http client ip ", clientIP, " and vpn ip ", session.Ipaddr, " is different."),
					"common_name", session.CommonName,
					"cid", session.Cid,
					"kid", session.Kid,
				)

				openvpnClient.SendCommandf(`client-deny %d %d "%s"`, session.Cid, session.Kid, "client rejected")

				w.WriteHeader(http.StatusForbidden)
				return
			}
		}

		logger.Info("initialize authorization via oauth2",
			"common_name", session.CommonName,
			"cid", session.Cid,
			"kid", session.Kid,
		)

		rp.AuthURLHandler(func() string {
			return sessionState
		}, oidcProvider.RelyingParty).ServeHTTP(w, r)
	})
}

func oauth2Callback(logger *slog.Logger, oidcProvider *Provider, conf config.Config, openvpnClient *openvpn.Client) http.Handler {
	return rp.CodeExchangeHandler(func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], sessionState string, rp rp.RelyingParty) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		session := state.NewEncoded(sessionState)
		if err := session.Decode(conf.Http.Secret); err != nil {
			logger.Warn(err.Error(),
				"subject", tokens.IDTokenClaims.Subject,
				"preferred_username", tokens.IDTokenClaims.PreferredUsername,
			)
			logger.Debug(sessionState)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		user, err := oidcProvider.OidcProvider.GetUser(ctx, tokens)
		if err != nil {
			logger.Error(err.Error(),
				"common_name", session.CommonName,
				"cid", session.Cid,
				"kid", session.Kid,
			)

			openvpnClient.SendCommandf(`client-deny %d %d "%s"`, session.Cid, session.Kid, "unable to fetch user data")

			return
		}

		if err := oidcProvider.OidcProvider.CheckUser(ctx, session, user, tokens); err != nil {
			logger.Warn(err.Error(),
				"subject", user.Subject,
				"preferred_username", user.PreferredUsername,
				"common_name", session.CommonName,
				"cid", session.Cid,
				"kid", session.Kid,
			)

			openvpnClient.SendCommandf(`client-deny %d %d "%s"`, session.Cid, session.Kid, "client rejected")

			if conf.Http.CallbackTemplate == nil || conf.Http.CallbackTemplate.Tree == nil {
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
			"subject", user.Subject,
			"preferred_username", user.PreferredUsername,
			"common_name", session.CommonName,
			"cid", session.Cid,
			"kid", session.Kid,
		)

		if conf.OpenVpn.AuthTokenUser {
			username := session.CommonName
			if user.PreferredUsername != "" {
				username = user.PreferredUsername
			} else if user.Subject != "" {
				username = user.Subject
			}

			b64Username := base64.StdEncoding.EncodeToString([]byte(username))
			openvpnClient.SendCommandf("client-auth %d %d\npush \"auth-token-user %s\"\nEND", session.Cid, session.Kid, b64Username)
		} else {
			openvpnClient.SendCommandf("client-auth-nt %d %d", session.Cid, session.Kid)
		}

		if conf.Http.CallbackTemplate == nil || conf.Http.CallbackTemplate.Tree == nil {
			_, _ = w.Write([]byte(callbackHtml))
		} else if err := conf.Http.CallbackTemplate.Execute(w, map[string]string{}); err != nil {
			logger.Error("executing template:", err)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}, oidcProvider.RelyingParty)
}
