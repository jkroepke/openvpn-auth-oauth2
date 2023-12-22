package oauth2

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/log"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/generic"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/github"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
	"github.com/zitadel/logging"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"golang.org/x/oauth2"
)

// NewProvider returns a [Provider] instance.
func NewProvider(logger *slog.Logger, conf config.Config, openvpnCallback OpenVPN) (Provider, error) {
	provider, err := newOidcProvider(conf)
	if err != nil {
		return Provider{}, err
	}

	authorizeParams, err := GetAuthorizeParams(conf.OAuth2.AuthorizeParams)
	if err != nil {
		return Provider{}, err
	}

	basePath := conf.HTTP.BaseURL.JoinPath("/oauth2")
	redirectURI := basePath.JoinPath("/callback").String()

	cookieKey := []byte(conf.HTTP.Secret)
	cookieOpt := []httphelper.CookieHandlerOpt{
		httphelper.WithMaxAge(int(conf.OpenVpn.AuthPendingTimeout.Seconds()) + 5),
		httphelper.WithPath(basePath.Path),
		httphelper.WithDomain(basePath.Hostname()),
	}

	if conf.HTTP.BaseURL.Scheme == "http" {
		cookieOpt = append(cookieOpt, httphelper.WithUnsecure())
	}

	cookieHandler := httphelper.NewCookieHandler(cookieKey, cookieKey, cookieOpt...)
	providerLogger := log.NewZitadelLogger(logger)

	options := []rp.Option{
		rp.WithLogger(providerLogger),
		rp.WithCookieHandler(cookieHandler),
		rp.WithVerifierOpts(rp.WithIssuedAtOffset(5 * time.Second)),
		rp.WithHTTPClient(&http.Client{Timeout: time.Second * 30, Transport: utils.NewUserAgentTransport(nil)}),
		rp.WithErrorHandler(func(w http.ResponseWriter, r *http.Request, errorType string, errorDesc string, encryptedSession string) {
			errorHandler(w, conf, logger, openvpnCallback, http.StatusInternalServerError, errorType, errorDesc, encryptedSession)
		}),
		rp.WithUnauthorizedHandler(func(w http.ResponseWriter, r *http.Request, desc string, encryptedSession string) {
			errorHandler(w, conf, logger, openvpnCallback, http.StatusUnauthorized, "Unauthorized", desc, encryptedSession)
		}),
	}

	if conf.OAuth2.Pkce {
		options = append(options, rp.WithPKCE(cookieHandler))
	}

	endpoints, err := provider.GetEndpoints(conf)
	if err != nil {
		return Provider{}, fmt.Errorf("error getting endpoints: %w", err)
	}

	scopes := conf.OAuth2.Scopes
	if len(scopes) == 0 {
		scopes = provider.GetDefaultScopes()
	}

	var relyingParty rp.RelyingParty

	if endpoints == (oauth2.Endpoint{}) {
		if !config.IsURLEmpty(conf.OAuth2.Endpoints.Discovery) {
			logger.Info(fmt.Sprintf(
				"discover oidc auto configuration with provider %s for issuer %s with custom discovery url %s",
				provider.GetName(), conf.OAuth2.Issuer.String(), conf.OAuth2.Endpoints.Discovery.String(),
			))

			options = append(options, rp.WithCustomDiscoveryUrl(conf.OAuth2.Endpoints.Discovery.String()))
		} else {
			logger.Info(fmt.Sprintf(
				"discover oidc auto configuration with provider %s for issuer %s",
				provider.GetName(), conf.OAuth2.Issuer.String(),
			))
		}

		relyingParty, err = rp.NewRelyingPartyOIDC(
			logging.ToContext(context.Background(), providerLogger),
			conf.OAuth2.Issuer.String(),
			conf.OAuth2.Client.ID,
			conf.OAuth2.Client.Secret.String(),
			redirectURI,
			scopes,
			options...,
		)
	} else {
		logger.Info(utils.StringConcat(
			"manually configure oauth2 provider with provider ",
			provider.GetName(), " and endpoints ", endpoints.AuthURL, " and ", endpoints.TokenURL,
		))

		rpConfig := &oauth2.Config{
			ClientID:     conf.OAuth2.Client.ID,
			ClientSecret: conf.OAuth2.Client.Secret.String(),
			RedirectURL:  redirectURI,
			Scopes:       scopes,
			Endpoint:     endpoints,
		}

		relyingParty, err = rp.NewRelyingPartyOAuth(rpConfig, options...)
	}

	if err != nil {
		return Provider{}, fmt.Errorf("error oauth2 provider: %w", err)
	}

	return Provider{
		RelyingParty:    relyingParty,
		OIDC:            provider,
		openvpn:         openvpnCallback,
		conf:            conf,
		logger:          logger,
		authorizeParams: authorizeParams,
	}, nil
}

func GetAuthorizeParams(authorizeParams string) ([]rp.URLParamOpt, error) {
	authorizeParamsQuery, err := url.ParseQuery(authorizeParams)
	if err != nil {
		return nil, fmt.Errorf("unable to parse '%s': %w", authorizeParams, err)
	}

	params := make([]rp.URLParamOpt, len(authorizeParamsQuery))

	var i int
	for key, value := range authorizeParamsQuery {
		if len(value) == 0 {
			return nil, fmt.Errorf("authorize param %s does not have values", key)
		}

		params[i] = rp.WithURLParam(key, value[0])
		i += 1
	}

	return params, nil
}

func newOidcProvider(conf config.Config) (oidcProvider, error) {
	switch conf.OAuth2.Provider {
	case generic.Name:
		return generic.NewProvider(conf), nil
	case github.Name:
		return github.NewProvider(conf), nil
	default:
		return nil, fmt.Errorf("unknown oauth2 provider: %s", conf.OAuth2.Provider)
	}
}

func errorHandler(
	w http.ResponseWriter, conf config.Config, logger *slog.Logger, openvpn OpenVPN,
	httpStatus int, errorType string, errorDesc string, encryptedSession string,
) {
	session := state.NewEncoded(encryptedSession)
	if err := session.Decode(conf.HTTP.Secret.String()); err == nil {
		logger = logger.With(
			slog.String("common_name", session.CommonName),
			slog.Uint64("cid", session.Client.Cid),
			slog.Uint64("kid", session.Client.Kid),
		)
		openvpn.DenyClient(logger, session.Client, "client rejected")
	} else {
		logger.Debug(fmt.Sprintf("errorHandler: %s", err.Error()))
	}

	logger.Warn(fmt.Sprintf("%s: %s", errorType, errorDesc))
	writeError(w, logger, conf, httpStatus, errorType, errorDesc)
}
