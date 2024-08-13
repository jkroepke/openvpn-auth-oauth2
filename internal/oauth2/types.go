package oauth2

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/storage"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type Provider struct {
	conf    config.Config
	logger  *slog.Logger
	storage *storage.Storage

	httpClient *http.Client

	rp.RelyingParty

	Provider        oidcProvider
	openvpn         OpenVPN
	authorizeParams []rp.URLParamOpt
}

type oidcProvider interface {
	CheckUser(ctx context.Context, session state.State, user types.UserData, tokens *oidc.Tokens[*idtoken.Claims]) error
	GetProviderConfig(conf config.Config) (types.ProviderConfig, error)
	GetName() string
	GetRefreshToken(tokens *oidc.Tokens[*idtoken.Claims]) (string, error)
	GetUser(ctx context.Context, logger *slog.Logger, tokens *oidc.Tokens[*idtoken.Claims]) (types.UserData, error)

	// Refresh initiates a non-interactive authentication against the sso provider.
	Refresh(ctx context.Context, logger *slog.Logger, relyingParty rp.RelyingParty, refreshToken string) (*oidc.Tokens[*idtoken.Claims], error)
	RevokeRefreshToken(ctx context.Context, logger *slog.Logger, relyingParty rp.RelyingParty, refreshToken string) error
}
