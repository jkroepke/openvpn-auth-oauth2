package generic

import (
	"context"
	"log/slog"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
)

func (p Provider) GetUser(ctx context.Context, logger *slog.Logger, tokens idtoken.IDToken, userinfo *types.UserInfo) (types.UserInfo, error) {
	if tokens.IDTokenClaims == nil {
		if tokens.IDToken == "" {
			// if tokens.Token.Extra("id_token") != nil {
			// 	logger.Warn("The provider has returned an 'id_token', however, it was configured as an OAUTH2 provider. " +
			// 		"As a result, user data validation cannot be performed. If you have defined endpoints in the configuration, please remove them and retry.")
			// 	logger.Debug("id_token", "id_token", tokens.Token.Extra("id_token"))
			// } else {
			logger.LogAttrs(ctx, slog.LevelWarn, "provider did not return a id_token. validation of user data is not possible.")
		} else {
			logger.LogAttrs(ctx, slog.LevelWarn, "provider did return a id_token, but it was not parsed correctly. Validation of user data is not possible."+
				" Enable DEBUG logs to see the raw token and report this to maintainer.")
			logger.LogAttrs(ctx, slog.LevelDebug, "id_token",
				slog.String("id_token", tokens.IDToken),
			)
		}

		return types.UserInfo{}, nil
	}

	var userData types.UserInfo

	if userinfo != nil {
		userData = *userinfo
	} else {
		userData = types.UserInfo{
			PreferredUsername: tokens.IDTokenClaims.PreferredUsername,
			Subject:           tokens.IDTokenClaims.Subject,
			Email:             tokens.IDTokenClaims.EMail,
			Groups:            tokens.IDTokenClaims.Groups,
		}
	}

	return userData, nil
}
