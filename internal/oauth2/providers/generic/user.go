package generic

import (
	"context"
	"log/slog"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func (p *Provider) GetUser(ctx context.Context, logger *slog.Logger, tokens *oidc.Tokens[*idtoken.Claims]) (types.UserData, error) {
	var (
		preferredUsername string
		subject           string
		email             string
	)

	if tokens.IDTokenClaims == nil {
		if tokens.IDToken == "" {
			// if tokens.Token.Extra("id_token") != nil {
			// 	logger.Warn("The provider has returned an 'id_token', however, it was configured as an OAUTH2 provider. " +
			// 		"As a result, user data validation cannot be performed. If you have defined endpoints in the configuration, please remove them and retry.")
			// 	logger.Debug("id_token", "id_token", tokens.Token.Extra("id_token"))
			// } else {
			logger.WarnContext(ctx, "provider did not return a id_token. Validation of user data is not possible.")
		} else {
			logger.WarnContext(ctx, "provider did return a id_token, but it was not parsed correctly. Validation of user data is not possible."+
				" Enable DEBUG logs to see the raw token and report this to maintainer.")
			logger.DebugContext(ctx, "id_token",
				slog.String("id_token", tokens.IDToken),
			)
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
