package oauth2

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/zitadel/oidc/v2/pkg/client/rp"
	httphelper "github.com/zitadel/oidc/v2/pkg/http"
	"golang.org/x/oauth2"
)

// NewProvider returns a [rp.RelyingParty] instance
func NewProvider(logger *slog.Logger, conf *config.Config) (rp.RelyingParty, error) {
	baseUrl, err := url.Parse(conf.Http.BaseUrl)
	if err != nil {
		return nil, fmt.Errorf("http.baseurl: %v", err)
	}

	redirectURI := fmt.Sprintf("%s/oauth2/callback", strings.TrimSuffix(conf.Http.BaseUrl, "/"))

	cookieKey := []byte(conf.Http.Secret)
	cookieOpt := []httphelper.CookieHandlerOpt{
		httphelper.WithMaxAge(1800),
		httphelper.WithPath(fmt.Sprintf("%s/oauth2", strings.TrimSuffix(baseUrl.Path, "/"))),
		httphelper.WithDomain(baseUrl.Hostname()),
	}

	if baseUrl.Scheme == "http" {
		cookieOpt = append(cookieOpt, httphelper.WithUnsecure())
	}

	cookieHandler := httphelper.NewCookieHandler(cookieKey, cookieKey, cookieOpt...)

	options := []rp.Option{
		rp.WithCookieHandler(cookieHandler),
		rp.WithErrorHandler(func(w http.ResponseWriter, r *http.Request, errorType string, errorDesc string, state string) {
			if conf.Http.CallbackTemplate == nil {
				http.Error(w, errorType+": "+errorDesc, http.StatusInternalServerError)
			} else {
				err := conf.Http.CallbackTemplate.Execute(w, map[string]string{
					"errorDesc": errorDesc,
					"errorType": errorType,
				})

				if err != nil {
					logger.Error("executing template:", err)
					w.WriteHeader(http.StatusInternalServerError)
				}
			}
		}),
	}

	if conf.Oauth2.Pkce {
		options = append(options, rp.WithPKCE(cookieHandler))
	}

	if conf.Oauth2.Endpoints.Auth == "" && conf.Oauth2.Endpoints.Token == "" {
		if conf.Oauth2.Endpoints.Discovery != "" {
			logger.Info(fmt.Sprintf("discover OIDC auto configuration for issuer %s with custom discovery url %s", conf.Oauth2.Issuer, conf.Oauth2.Endpoints.Discovery))
			options = append(options, rp.WithCustomDiscoveryUrl(conf.Oauth2.Endpoints.Discovery))
		} else {
			logger.Info(fmt.Sprintf("discover OIDC auto configuration for issuer %s", conf.Oauth2.Issuer))
		}

		return rp.NewRelyingPartyOIDC(
			conf.Oauth2.Issuer,
			conf.Oauth2.Client.Id,
			conf.Oauth2.Client.Secret,
			redirectURI,
			conf.Oauth2.Scopes,
			options...,
		)
	}

	logger.Info(fmt.Sprintf("manually configure oauth2 provider with endpoints %s and %s", conf.Oauth2.Endpoints.Auth, conf.Oauth2.Endpoints.Token))

	rpConfig := &oauth2.Config{
		ClientID:     conf.Oauth2.Client.Id,
		ClientSecret: conf.Oauth2.Client.Secret,
		RedirectURL:  redirectURI,
		Scopes:       conf.Oauth2.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  conf.Oauth2.Endpoints.Auth,
			TokenURL: conf.Oauth2.Endpoints.Token,
		},
	}

	return rp.NewRelyingPartyOAuth(rpConfig, options...)
}
