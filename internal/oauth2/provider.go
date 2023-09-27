package oauth2

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/generic"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/github"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
	"github.com/zitadel/oidc/v2/pkg/client/rp"
	httphelper "github.com/zitadel/oidc/v2/pkg/http"
	"github.com/zitadel/oidc/v2/pkg/oidc"
	"golang.org/x/oauth2"
)

type Provider struct {
	rp.RelyingParty
	OidcProvider
}

type OidcProvider interface {
	CheckUser(ctx context.Context, session *state.State, user *types.UserData, tokens *oidc.Tokens[*oidc.IDTokenClaims]) error
	GetEndpoints(conf *config.Config) (*oauth2.Endpoint, error)
	GetName() string
	GetUser(ctx context.Context, tokens *oidc.Tokens[*oidc.IDTokenClaims]) (*types.UserData, error)
}

// NewProvider returns a [rp.RelyingParty] instance
func NewProvider(logger *slog.Logger, conf *config.Config) (*Provider, error) {
	oidcProvider, err := NewOidcProvider(conf)
	if err != nil {
		return nil, err
	}

	redirectURI := utils.StringConcat(strings.TrimSuffix(conf.Http.BaseUrl.String(), "/"), "/oauth2/callback")

	cookieKey := []byte(conf.Http.Secret)
	cookieOpt := []httphelper.CookieHandlerOpt{
		httphelper.WithMaxAge(1800),
		httphelper.WithPath(utils.StringConcat(strings.TrimSuffix(conf.Http.BaseUrl.Path, "/"), "/oauth2")),
		httphelper.WithDomain(conf.Http.BaseUrl.Hostname()),
	}

	if conf.Http.BaseUrl.Scheme == "http" {
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

	endpoints, err := oidcProvider.GetEndpoints(conf)
	if err != nil {
		return nil, err
	}

	if endpoints == nil {
		if !utils.IsUrlEmpty(conf.Oauth2.Endpoints.Discovery) {
			logger.Info(utils.StringConcat("discover OIDC auto configuration with provider ", oidcProvider.GetName(), "for issuer ", conf.Oauth2.Issuer.String(), "with custom discovery url", conf.Oauth2.Endpoints.Discovery.String()))
			options = append(options, rp.WithCustomDiscoveryUrl(conf.Oauth2.Endpoints.Discovery.String()))
		} else {
			logger.Info(utils.StringConcat("discover OIDC auto configuration with provider ", oidcProvider.GetName(), "for issuer ", conf.Oauth2.Issuer.String()))
		}

		relayingParty, err := rp.NewRelyingPartyOIDC(
			conf.Oauth2.Issuer.String(),
			conf.Oauth2.Client.Id,
			conf.Oauth2.Client.Secret,
			redirectURI,
			conf.Oauth2.Scopes,
			options...,
		)

		if err != nil {
			return nil, err
		}

		return &Provider{
			RelyingParty: relayingParty,
			OidcProvider: oidcProvider,
		}, nil
	}

	logger.Info(utils.StringConcat("manually configure oauth2 provider with provider ", oidcProvider.GetName(), " and endpoints ", endpoints.AuthURL, " and ", endpoints.TokenURL))

	rpConfig := &oauth2.Config{
		ClientID:     conf.Oauth2.Client.Id,
		ClientSecret: conf.Oauth2.Client.Secret,
		RedirectURL:  redirectURI,
		Scopes:       conf.Oauth2.Scopes,
		Endpoint:     *endpoints,
	}

	relayingParty, err := rp.NewRelyingPartyOAuth(rpConfig, options...)
	if err != nil {
		return nil, err
	}

	return &Provider{
		RelyingParty: relayingParty,
		OidcProvider: oidcProvider,
	}, nil
}

func NewOidcProvider(conf *config.Config) (OidcProvider, error) {
	switch conf.Oauth2.Provider {
	case "generic":
		return generic.NewProvider(conf), nil
	case "github":
		return github.NewProvider(conf), nil
	default:
		return nil, errors.New(utils.StringConcat("unknown oauth2 provider: ", conf.Oauth2.Provider))
	}
}
