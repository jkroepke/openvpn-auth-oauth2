package oauth2

import (
	"context"
	"log/slog"

	types2 "github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/tokenstorage"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type Client struct {
	relyingParty rp.RelyingParty
	openvpn      openvpnManagementClient

	conf    types2.Config
	logger  *slog.Logger
	storage tokenstorage.Storage

	provider        Provider
	authorizeParams []rp.URLParamOpt
}

type Provider interface {
	CheckUser(ctx context.Context, session state.State, user types.UserData, tokens *oidc.Tokens[*idtoken.Claims]) error
	GetProviderConfig() (types.ProviderConfig, error)
	GetName() string
	GetRefreshToken(tokens *oidc.Tokens[*idtoken.Claims]) (string, error)
	GetUser(ctx context.Context, logger *slog.Logger, tokens *oidc.Tokens[*idtoken.Claims]) (types.UserData, error)

	// Refresh initiates a non-interactive authentication against the sso provider.
	Refresh(ctx context.Context, logger *slog.Logger, relyingParty rp.RelyingParty, refreshToken string) (*oidc.Tokens[*idtoken.Claims], error)
	RevokeRefreshToken(ctx context.Context, logger *slog.Logger, relyingParty rp.RelyingParty, refreshToken string) error
}
