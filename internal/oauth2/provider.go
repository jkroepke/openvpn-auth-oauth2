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
	"github.com/jkroepke/openvpn-auth-oauth2/internal/storage"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
	"github.com/zitadel/logging"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	expslog "golang.org/x/exp/slog"
	"golang.org/x/oauth2"
)

// New returns a [Provider] instance.
func New(logger *slog.Logger, conf config.Config, storageClient *storage.Storage) *Provider {
	return &Provider{
		storage: storageClient,
		conf:    conf,
		logger:  logger,
	}
}

// Discover initiate the discovery of OIDC provider.
func (p *Provider) Discover(openvpn OpenVPN) error {
	var err error

	p.openvpn = openvpn

	p.OIDC, err = newOidcProvider(p.conf)
	if err != nil {
		return err
	}

	endpoints, err := p.OIDC.GetEndpoints(p.conf)
	if err != nil {
		return fmt.Errorf("error getting endpoints: %w", err)
	}

	p.authorizeParams, err = GetAuthorizeParams(p.conf.OAuth2.AuthorizeParams)
	if err != nil {
		return err
	}

	providerLogger := log.NewZitadelLogger(p.logger)

	basePath := p.conf.HTTP.BaseURL.JoinPath("/oauth2")
	redirectURI := basePath.JoinPath("/callback").String()
	options := p.getProviderOptions(providerLogger, basePath)

	scopes := p.conf.OAuth2.Scopes
	if len(scopes) == 0 {
		scopes = p.OIDC.GetDefaultScopes()
	}

	if endpoints == (oauth2.Endpoint{}) {
		if !config.IsURLEmpty(p.conf.OAuth2.Endpoints.Discovery) {
			p.logger.Info(fmt.Sprintf(
				"discover oidc auto configuration with provider %s for issuer %s with custom discovery url %s",
				p.OIDC.GetName(), p.conf.OAuth2.Issuer.String(), p.conf.OAuth2.Endpoints.Discovery.String(),
			))

			options = append(options, rp.WithCustomDiscoveryUrl(p.conf.OAuth2.Endpoints.Discovery.String()))
		} else {
			p.logger.Info(fmt.Sprintf(
				"discover oidc auto configuration with provider %s for issuer %s",
				p.OIDC.GetName(), p.conf.OAuth2.Issuer.String(),
			))
		}

		p.RelyingParty, err = rp.NewRelyingPartyOIDC(
			logging.ToContext(context.Background(), providerLogger),
			p.conf.OAuth2.Issuer.String(),
			p.conf.OAuth2.Client.ID,
			p.conf.OAuth2.Client.Secret.String(),
			redirectURI,
			scopes,
			options...,
		)
	} else {
		p.logger.Info(fmt.Sprintf(
			"manually configure oauth2 provider with provider %s and endpoints %s and %s",
			p.OIDC.GetName(), endpoints.AuthURL, endpoints.TokenURL,
		))

		rpConfig := &oauth2.Config{
			ClientID:     p.conf.OAuth2.Client.ID,
			ClientSecret: p.conf.OAuth2.Client.Secret.String(),
			RedirectURL:  redirectURI,
			Scopes:       scopes,
			Endpoint:     endpoints,
		}

		p.RelyingParty, err = rp.NewRelyingPartyOAuth(rpConfig, options...)
	}

	if err != nil {
		return fmt.Errorf("error oauth2 provider: %w", err)
	}

	return nil
}

func (p *Provider) getProviderOptions(providerLogger *expslog.Logger, basePath *url.URL) []rp.Option {
	cookieKey := []byte(p.conf.HTTP.Secret)
	cookieOpt := []httphelper.CookieHandlerOpt{
		httphelper.WithMaxAge(int(p.conf.OpenVpn.AuthPendingTimeout.Seconds()) + 5),
		httphelper.WithPath(basePath.Path),
		httphelper.WithDomain(basePath.Hostname()),
	}

	if p.conf.HTTP.BaseURL.Scheme == "http" {
		cookieOpt = append(cookieOpt, httphelper.WithUnsecure())
	}

	cookieHandler := httphelper.NewCookieHandler(cookieKey, cookieKey, cookieOpt...)

	verifierOpts := []rp.VerifierOption{
		rp.WithIssuedAtMaxAge(30 * time.Minute),
		rp.WithIssuedAtOffset(5 * time.Second),
	}

	if p.conf.OAuth2.Nonce {
		verifierOpts = append(verifierOpts, rp.WithNonce(func(ctx context.Context) string {
			if nonce, ok := ctx.Value(ctxNonce{}).(string); ok {
				return nonce
			}

			return ""
		}))
	}

	options := []rp.Option{
		rp.WithLogger(providerLogger),
		rp.WithCookieHandler(cookieHandler),
		rp.WithVerifierOpts(verifierOpts...),
		rp.WithHTTPClient(&http.Client{Timeout: time.Second * 30, Transport: utils.NewUserAgentTransport(nil)}),
		rp.WithErrorHandler(func(w http.ResponseWriter, r *http.Request, errorType string, errorDesc string, encryptedSession string) {
			errorHandler(w, p.conf, p.logger, p.openvpn, http.StatusInternalServerError, errorType, errorDesc, encryptedSession)
		}),
		rp.WithUnauthorizedHandler(func(w http.ResponseWriter, r *http.Request, desc string, encryptedSession string) {
			errorHandler(w, p.conf, p.logger, p.openvpn, http.StatusUnauthorized, "Unauthorized", desc, encryptedSession)
		}),
	}

	if p.conf.OAuth2.Pkce {
		options = append(options, rp.WithPKCE(cookieHandler))
	}

	return options
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
		i++
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
