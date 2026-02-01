package oauth2

import (
	"context"
	"log/slog"

	"github.com/google/cel-go/cel"
	types2 "github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/tokenstorage"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
)

type Client struct {
	relyingParty    rp.RelyingParty
	openvpn         openvpnManagementClient
	storage         tokenstorage.Storage
	provider        Provider
	celEvalPrg      cel.Program
	logger          *slog.Logger
	authorizeParams []rp.URLParamOpt
	conf            types2.Config
}

type Provider interface {
	CheckUser(ctx context.Context, session state.State, user types.UserInfo, tokens idtoken.IDToken) error
	GetProviderConfig() (types.ProviderConfig, error)
	GetName() string
	GetRefreshToken(tokens idtoken.IDToken) (string, error)
	GetUser(ctx context.Context, logger *slog.Logger, tokens idtoken.IDToken, userinfo *types.UserInfo) (types.UserInfo, error)

	// Refresh initiates a non-interactive authentication against the sso provider.
	Refresh(ctx context.Context, logger *slog.Logger, relyingParty rp.RelyingParty, refreshToken string) (idtoken.IDToken, error)
	RevokeRefreshToken(ctx context.Context, logger *slog.Logger, relyingParty rp.RelyingParty, refreshToken string) error
}

// clientConfigToken is used to store additional information on the client side.
type clientConfigToken struct {
	Username string   `json:"username,omitempty"`
	State    string   `json:"state,omitempty"`
	Profiles []string `json:"profiles,omitempty"`
}
