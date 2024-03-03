package generic

import (
	"context"
	"log/slog"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func (p *Provider) GetUser(_ context.Context, logger *slog.Logger, tokens *oidc.Tokens[*idtoken.Claims]) (types.UserData, error) {
	var (
		preferredUsername string
		subject           string
		email             string
	)

	if tokens.IDTokenClaims == nil {
		if tokens.IDToken == "" {
			logger.Warn("provider did not return a id_token. Validation of user data is not possible.")
		} else {
			logger.Warn("provider did return a id_token, but it was not parsed correctly. Validation of user data is not possible." +
				" Enable DEBUG logs to see the raw token and report this to maintainer.")
			logger.Debug("id_token", "id_token", tokens.IDToken)
		}
	} else {
		preferredUsername = tokens.IDTokenClaims.PreferredUsername
		subject = tokens.IDTokenClaims.Subject
		email = tokens.IDTokenClaims.EMail
	}

	return types.UserData{
		PreferredUsername: preferredUsername,
		Subject:           subject,
		Email:             email,
	}, nil
}
