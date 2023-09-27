package oauth2

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/github"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/oidc"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
	"github.com/zitadel/oidc/v2/pkg/client/rp"
	httphelper "github.com/zitadel/oidc/v2/pkg/http"
	token "github.com/zitadel/oidc/v2/pkg/oidc"
	"golang.org/x/oauth2"
)

type Provider struct {
	rp.RelyingParty
	Connector
}

type Connector interface {
	CheckUser(ctx context.Context, session *state.State, user *types.UserData, tokens *token.Tokens[*token.IDTokenClaims]) error
	GetUser(ctx context.Context, tokens *token.Tokens[*token.IDTokenClaims]) (*types.UserData, error)
}

// NewProvider returns a [rp.RelyingParty] instance
func NewProvider(logger *slog.Logger, conf *config.Config) (*Provider, error) {
	tokenValidator, err := NewTokenValidateProvider(conf)
	if err != nil {
		return nil, err
	}

	redirectURI := fmt.Sprintf("%s/oauth2/callback", strings.TrimSuffix(conf.Http.BaseUrl.String(), "/"))

	cookieKey := []byte(conf.Http.Secret)
	cookieOpt := []httphelper.CookieHandlerOpt{
		httphelper.WithMaxAge(1800),
		httphelper.WithPath(fmt.Sprintf("%s/oauth2", strings.TrimSuffix(conf.Http.BaseUrl.Path, "/"))),
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

	if utils.IsUrlEmpty(conf.Oauth2.Endpoints.Auth) && utils.IsUrlEmpty(conf.Oauth2.Endpoints.Token) {
		if !utils.IsUrlEmpty(conf.Oauth2.Endpoints.Discovery) {
			logger.Info(fmt.Sprintf("discover OIDC auto configuration for issuer %s with custom discovery url %s", conf.Oauth2.Issuer.String(), conf.Oauth2.Endpoints.Discovery.String()))
			options = append(options, rp.WithCustomDiscoveryUrl(conf.Oauth2.Endpoints.Discovery.String()))
		} else {
			logger.Info(fmt.Sprintf("discover OIDC auto configuration for issuer %s", conf.Oauth2.Issuer.String()))
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
			Connector:    tokenValidator,
		}, nil
	}

	logger.Info(fmt.Sprintf("manually configure oauth2 provider with endpoints %s and %s", conf.Oauth2.Endpoints.Auth.String(), conf.Oauth2.Endpoints.Token.String()))

	rpConfig := &oauth2.Config{
		ClientID:     conf.Oauth2.Client.Id,
		ClientSecret: conf.Oauth2.Client.Secret,
		RedirectURL:  redirectURI,
		Scopes:       conf.Oauth2.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  conf.Oauth2.Endpoints.Auth.String(),
			TokenURL: conf.Oauth2.Endpoints.Token.String(),
		},
	}

	relayingParty, err := rp.NewRelyingPartyOAuth(rpConfig, options...)
	if err != nil {
		return nil, err
	}

	return &Provider{
		RelyingParty: relayingParty,
		Connector:    tokenValidator,
	}, nil
}

func NewTokenValidateProvider(conf *config.Config) (Connector, error) {
	switch conf.Oauth2.Provider {
	case "oidc":
		return oidc.NewProvider(conf), nil
	case "github":
		return github.NewProvider(conf), nil
	default:
		return nil, fmt.Errorf("unknown oauth2 provider: %s", conf.Oauth2.Provider)
	}
}
