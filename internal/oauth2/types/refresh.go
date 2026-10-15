package types

import (
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/sessionregistry"
)

// RefreshResult is the outcome of a successful non-interactive authentication.
type RefreshResult struct {
	// Tokens is the refreshed token set. It is nil when
	// oauth2.refresh.validate-user is false.
	Tokens *idtoken.IDToken
	// Identity is the OIDC identity of the client.
	Identity sessionregistry.Identity
	// User is the validated user. With oauth2.refresh.validate-user=false
	// only the username is set.
	User UserInfo
	// ClientConfigNames are the client config profiles stored at login.
	ClientConfigNames []string
}
