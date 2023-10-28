package oauth2

import (
	"context"

	"github.com/jkroepke/openvpn-auth-oauth2/pkg/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/pkg/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/pkg/internal/types"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/oauth2"
)

type Provider struct {
	rp.RelyingParty
	OIDC oidcProvider
}

type oidcProvider interface {
	CheckUser(ctx context.Context, session state.State, user types.UserData, tokens *oidc.Tokens[*oidc.IDTokenClaims]) error
	GetEndpoints(conf config.Config) (oauth2.Endpoint, error)
	GetName() string
	GetUser(ctx context.Context, tokens *oidc.Tokens[*oidc.IDTokenClaims]) (types.UserData, error)
}
