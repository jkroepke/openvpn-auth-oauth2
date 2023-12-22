package oauth2

import (
	"context"
	"log/slog"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/storage"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/types"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/oauth2"
)

type Provider struct {
	conf    config.Config
	logger  *slog.Logger
	storage *storage.Storage

	rp.RelyingParty

	OIDC            oidcProvider
	openvpn         OpenVPN
	authorizeParams []rp.URLParamOpt
}

type oidcProvider interface {
	CheckUser(ctx context.Context, session state.State, user types.UserData, tokens *oidc.Tokens[*idtoken.Claims]) error
	GetDefaultScopes() []string
	GetEndpoints(conf config.Config) (oauth2.Endpoint, error)
	GetName() string
	GetUser(ctx context.Context, tokens *oidc.Tokens[*idtoken.Claims]) (types.UserData, error)
}
