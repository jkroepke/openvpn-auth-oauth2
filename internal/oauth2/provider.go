package oauth2

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/tokenstorage"
	"github.com/zitadel/logging"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/oauth2"
)

// New returns a [Client] instance.
func New(ctx context.Context, logger *slog.Logger, conf config.Config, httpClient *http.Client, tokenStorage tokenstorage.Storage,
	provider Provider, openvpn openvpnManagementClient,
) (*Client, error) {
	providerConfig, err := provider.GetProviderConfig()
	if err != nil {
		return nil, fmt.Errorf("error fetch configuration for provider %s: %w", provider.GetName(), err)
	}

	client := &Client{
		storage:         tokenStorage,
		openvpn:         openvpn,
		conf:            conf,
		logger:          logger,
		provider:        provider,
		authorizeParams: make([]rp.URLParamOpt, 0, len(conf.OAuth2.AuthorizeParams)+len(providerConfig.AuthCodeOptions)+1), // +1 for nonce
	}

	authorizeParams, err := getAuthorizeParams(conf.OAuth2.AuthorizeParams)
	if err != nil {
		return nil, fmt.Errorf("error parsing authorize params: %w", err)
	}

	client.authorizeParams = append(client.authorizeParams, authorizeParams...)

	if providerConfig.AuthCodeOptions != nil {
		client.authorizeParams = append(client.authorizeParams, func() []oauth2.AuthCodeOption {
			return providerConfig.AuthCodeOptions
		})
	}

	options := client.getRelyingPartyOptions(httpClient)

	scopes := conf.OAuth2.Scopes
	if len(scopes) == 0 {
		scopes = providerConfig.Scopes
	}

	if providerConfig.Endpoint == (oauth2.Endpoint{}) {
		client.relyingParty, err = newOIDCRelyingParty(ctx, logger, conf, provider, scopes, options)
		if err != nil {
			return nil, err
		}
	} else {
		client.relyingParty, err = newOAuthRelyingParty(ctx, logger, conf, provider, scopes, options, providerConfig)
		if err != nil {
			return nil, err
		}
	}

	err = client.initializeCELValidation()
	if err != nil {
		return nil, err
	}

	return client, nil
}

func (c *Client) initializeCELValidation() error {
	if c.conf.OAuth2.Validate.CEL == "" {
		return nil
	}

	env, err := cel.NewEnv(
		cel.VariableWithDoc("authMode", cel.StringType, "The authentication mode used (e.g., 'interactive', 'non-interactive')"),
		cel.VariableWithDoc("openVPNSessionState", cel.StringType, "The OpenVPN session state "+
			"(e.g., '', 'Empty', 'Initial', 'Authenticated', 'Expired', 'Invalid', 'AuthenticatedEmptyUser', 'ExpiredEmptyUser')"),
		cel.VariableWithDoc("openVPNUserCommonName", cel.StringType, "The common name of the OpenVPN user"),
		cel.VariableWithDoc("openVPNUserIPAddr", cel.StringType, "The IP address of the OpenVPN user"),
		cel.VariableWithDoc("oauth2TokenClaims", cel.MapType(cel.StringType, cel.DynType), "The claims of the OAuth2 ID token"),
		ext.Strings(ext.StringsVersion(4)),
	)
	if err != nil {
		return fmt.Errorf("failed to create CEL environment: %w", err)
	}

	prg, issues := env.Compile(c.conf.OAuth2.Validate.CEL)
	if issues.Err() != nil {
		return fmt.Errorf("failed to compile CEL expression: %w", issues.Err())
	}

	c.celEvalPrg, err = env.Program(prg)
	if err != nil {
		return fmt.Errorf("failed to create CEL program: %w", err)
	}

	return nil
}

// newOIDCRelyingParty creates a new [rp.NewRelyingPartyOIDC]. This is used for providers that support OIDC.
func newOIDCRelyingParty(
	ctx context.Context, logger *slog.Logger, conf config.Config, provider Provider, scopes []string, options []rp.Option,
) (rp.RelyingParty, error) {
	discoveryURL := conf.OAuth2.Endpoints.Discovery
	if discoveryURL != nil && (discoveryURL.Scheme != "" || discoveryURL.Host != "") {
		logger.LogAttrs(ctx, slog.LevelInfo, fmt.Sprintf(
			"discover oidc auto configuration with provider %s for issuer %s with custom discovery url %s",
			provider.GetName(), conf.OAuth2.Issuer.String(), conf.OAuth2.Endpoints.Discovery.String(),
		))

		options = append(options, rp.WithCustomDiscoveryUrl(conf.OAuth2.Endpoints.Discovery.String()))
	} else {
		logger.LogAttrs(ctx, slog.LevelInfo, fmt.Sprintf(
			"discover oidc auto configuration with provider %s for issuer %s",
			provider.GetName(), conf.OAuth2.Issuer.String(),
		))
	}

	replyingParty, err := rp.NewRelyingPartyOIDC(
		logging.ToContext(ctx, logger),
		conf.OAuth2.Issuer.String(),
		conf.OAuth2.Client.ID,
		conf.OAuth2.Client.Secret.String(),
		conf.HTTP.BaseURL.JoinPath("/oauth2/callback").String(),
		scopes,
		options...,
	)
	if err != nil {
		return nil, fmt.Errorf("error oidc provider: %w", err)
	}

	return replyingParty, nil
}

// newOAuthRelyingParty creates a new [rp.NewRelyingPartyOAuth]. This is used for providers that do not support OIDC.
func newOAuthRelyingParty(
	ctx context.Context, logger *slog.Logger, conf config.Config, provider Provider, scopes []string, options []rp.Option, providerConfig types.ProviderConfig,
) (rp.RelyingParty, error) {
	logger.LogAttrs(ctx, slog.LevelInfo, fmt.Sprintf(
		"manually configure oauth2 provider with provider %s and providerConfig %s and %s",
		provider.GetName(), providerConfig.AuthURL, providerConfig.TokenURL,
	))

	if provider.GetName() == "generic" {
		logger.LogAttrs(ctx, slog.LevelWarn, "generic provider with manual configuration is used. Validation of user data is not possible.")
	}

	replyingParty, err := rp.NewRelyingPartyOAuth(&oauth2.Config{
		ClientID:     conf.OAuth2.Client.ID,
		ClientSecret: conf.OAuth2.Client.Secret.String(),
		RedirectURL:  conf.HTTP.BaseURL.JoinPath("/oauth2/callback").String(),
		Scopes:       scopes,
		Endpoint:     providerConfig.Endpoint,
	}, options...)
	if err != nil {
		return nil, fmt.Errorf("error oauth2 provider: %w", err)
	}

	return replyingParty, nil
}

func (c *Client) getRelyingPartyOptions(httpClient *http.Client) []rp.Option {
	basePath := c.conf.HTTP.BaseURL.JoinPath("/oauth2/")
	cookieKey := []byte(c.conf.HTTP.Secret)
	cookieOpt := []httphelper.CookieHandlerOpt{
		httphelper.WithMaxAge(int(c.conf.OpenVPN.AuthPendingTimeout.Seconds()) + 5),
		httphelper.WithPath(fmt.Sprintf("/%s/", strings.Trim(basePath.Path, "/"))),
		httphelper.WithDomain(basePath.Hostname()),
	}

	if c.conf.HTTP.BaseURL.Scheme == "http" {
		cookieOpt = append(cookieOpt, httphelper.WithUnsecure())
	}

	cookieHandler := httphelper.NewCookieHandler(cookieKey, cookieKey, cookieOpt...)

	verifierOpts := make([]rp.VerifierOption, 0, 4)
	verifierOpts = append(verifierOpts,
		rp.WithIssuedAtMaxAge(30*time.Minute),
		rp.WithIssuedAtOffset(5*time.Second),
	)

	if c.conf.OAuth2.Validate.Acr != nil {
		verifierOpts = append(verifierOpts, rp.WithACRVerifier(oidc.DefaultACRVerifier(c.conf.OAuth2.Validate.Acr)))
	}

	if c.conf.OAuth2.Nonce {
		verifierOpts = append(verifierOpts, rp.WithNonce(func(ctx context.Context) string {
			if nonce, ok := ctx.Value(types.CtxNonce{}).(string); ok {
				return nonce
			}

			return ""
		}))
	}

	options := make([]rp.Option, 0, 10)
	options = append(options,
		rp.WithAuthStyle(c.conf.OAuth2.AuthStyle.AuthStyle()),
		rp.WithSigningAlgsFromDiscovery(),
		rp.WithLogger(c.logger),
		rp.WithCookieHandler(cookieHandler),
		rp.WithVerifierOpts(verifierOpts...),
		rp.WithHTTPClient(httpClient),
		rp.WithErrorHandler(func(w http.ResponseWriter, r *http.Request, errorType, errorDesc, encryptedSession string) {
			c.httpErrorHandler(r.Context(), w, http.StatusInternalServerError, errorType, errorDesc, encryptedSession)
		}),
		rp.WithUnauthorizedHandler(func(w http.ResponseWriter, r *http.Request, errorDesc, encryptedSession string) {
			c.httpErrorHandler(r.Context(), w, http.StatusUnauthorized, "Unauthorized", errorDesc, encryptedSession)
		}),
	)

	if c.conf.OAuth2.PKCE {
		options = append(options, rp.WithPKCE(cookieHandler))
	}

	if c.conf.OAuth2.Client.PrivateKey.String() != "" {
		options = append(options, rp.WithJWTProfile(rp.SignerFromKeyAndKeyID(
			[]byte(c.conf.OAuth2.Client.PrivateKey.String()),
			c.conf.OAuth2.Client.PrivateKeyID,
		)))
	}

	return options
}
