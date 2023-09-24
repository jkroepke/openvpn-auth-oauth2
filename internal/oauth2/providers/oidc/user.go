package oidc

import (
	"context"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/types"
	"github.com/zitadel/oidc/v2/pkg/oidc"
)

func (p *Provider) GetUser(_ context.Context, tokens *oidc.Tokens[*oidc.IDTokenClaims]) (*types.UserData, error) {
	var (
		preferredUsername string
		subject           string
	)

	if tokens.IDTokenClaims != nil {
		preferredUsername = tokens.IDTokenClaims.PreferredUsername
	}

	if tokens.IDTokenClaims != nil {
		subject = tokens.IDTokenClaims.Subject
	}

	return &types.UserData{
		PreferredUsername: preferredUsername,
		Subject:           subject,
	}, nil
}
