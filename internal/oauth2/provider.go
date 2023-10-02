package oauth2

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/generic"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/github"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
	"github.com/zitadel/oidc/v2/pkg/client/rp"
	httphelper "github.com/zitadel/oidc/v2/pkg/http"
	"golang.org/x/oauth2"
)

// NewProvider returns a [rp.RelyingParty] instance.
func NewProvider(logger *slog.Logger, conf config.Config) (Provider, error) {
	provider, err := newOidcProvider(conf)
	if err != nil {
		return Provider{}, err
	}

	redirectURI := utils.StringConcat(strings.TrimSuffix(conf.HTTP.BaseURL.String(), "/"), "/oauth2/callback")

	cookieKey := []byte(conf.HTTP.Secret)
	cookieOpt := []httphelper.CookieHandlerOpt{
		httphelper.WithMaxAge(1800),
		httphelper.WithPath(utils.StringConcat(strings.TrimSuffix(conf.HTTP.BaseURL.Path, "/"), "/oauth2")),
		httphelper.WithDomain(conf.HTTP.BaseURL.Hostname()),
	}

	if conf.HTTP.BaseURL.Scheme == "http" {
		cookieOpt = append(cookieOpt, httphelper.WithUnsecure())
	}

	cookieHandler := httphelper.NewCookieHandler(cookieKey, cookieKey, cookieOpt...)

	options := []rp.Option{
		rp.WithCookieHandler(cookieHandler),
		rp.WithErrorHandler(func(w http.ResponseWriter, r *http.Request, errorType string, errorDesc string, state string) {
			if conf.HTTP.CallbackTemplate == nil {
				http.Error(w, errorType+": "+errorDesc, http.StatusInternalServerError)
			} else {
				err := conf.HTTP.CallbackTemplate.Execute(w, map[string]string{
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

	if conf.OAuth2.Pkce {
		options = append(options, rp.WithPKCE(cookieHandler))
	}

	endpoints, err := provider.GetEndpoints(conf)
	if err != nil {
		return Provider{}, fmt.Errorf("error getting endpoints: %w", err)
	}

	if endpoints == (oauth2.Endpoint{}) {
		if !utils.IsURLEmpty(conf.OAuth2.Endpoints.Discovery) {
			logger.Info(utils.StringConcat(
				"discover oidc auto configuration with provider ",
				provider.GetName(), "for issuer ", conf.OAuth2.Issuer.String(),
				"with custom discovery url", conf.OAuth2.Endpoints.Discovery.String(),
			))

			options = append(options, rp.WithCustomDiscoveryUrl(conf.OAuth2.Endpoints.Discovery.String()))
		} else {
			logger.Info(utils.StringConcat(
				"discover oidc auto configuration with provider ",
				provider.GetName(), "for issuer ", conf.OAuth2.Issuer.String(),
			))
		}

		return newProviderWithDiscovery(conf, provider, options, redirectURI)
	}

	logger.Info(utils.StringConcat(
		"manually configure oauth2 provider with provider ",
		provider.GetName(), " and endpoints ", endpoints.AuthURL, " and ", endpoints.TokenURL,
	))

	return newProviderWithEndpoints(conf, provider, options, redirectURI, endpoints)
}

func newProviderWithEndpoints(
	conf config.Config, provider oidcProvider, options []rp.Option, redirectURI string, endpoints oauth2.Endpoint,
) (Provider, error) {
	rpConfig := &oauth2.Config{
		ClientID:     conf.OAuth2.Client.ID,
		ClientSecret: conf.OAuth2.Client.Secret,
		RedirectURL:  redirectURI,
		Scopes:       conf.OAuth2.Scopes,
		Endpoint:     endpoints,
	}

	relayingParty, err := rp.NewRelyingPartyOAuth(rpConfig, options...)
	if err != nil {
		return Provider{}, fmt.Errorf("error creating relaying party: %w", err)
	}

	return Provider{
		RelyingParty: relayingParty,
		OIDC:         provider,
	}, nil
}

func newProviderWithDiscovery(
	conf config.Config, provider oidcProvider, options []rp.Option, redirectURI string,
) (Provider, error) {
	relayingParty, err := rp.NewRelyingPartyOIDC(
		conf.OAuth2.Issuer.String(),
		conf.OAuth2.Client.ID,
		conf.OAuth2.Client.Secret,
		redirectURI,
		conf.OAuth2.Scopes,
		options...,
	)
	if err != nil {
		return Provider{}, fmt.Errorf("error creating relaying party: %w", err)
	}

	return Provider{
		RelyingParty: relayingParty,
		OIDC:         provider,
	}, nil
}

func newOidcProvider(conf config.Config) (oidcProvider, error) {
	switch conf.OAuth2.Provider {
	case "generic":
		return generic.NewProvider(conf), nil
	case "github":
		return github.NewProvider(conf), nil
	default:
		return nil, fmt.Errorf("unknown oauth2 provider: %s", conf.OAuth2.Provider)
	}
}
