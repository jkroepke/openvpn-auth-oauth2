package generic

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
)

func (p Provider) GetUser(ctx context.Context, logger *slog.Logger, idToken idtoken.IDToken, userinfo *types.UserInfo) (types.UserInfo, error) {
	if userinfo != nil {
		return *userinfo, nil
	}

	if idToken.IDTokenClaims == nil {
		if idToken.IDToken == "" {
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
				slog.String("id_token", idToken.IDToken),
			)
		}

		return types.UserInfo{}, nil
	}

	var groups []string

	if len(p.Conf.OAuth2.Validate.Groups) != 0 {
		var err error

		groups, err = p.extractGroups(ctx, logger, idToken)
		if err != nil {
			return types.UserInfo{}, err
		}
	}

	username, err := p.extractUsernameFromToken(idToken)
	if err != nil {
		return types.UserInfo{}, err
	}

	return types.UserInfo{
		Username: username,
		Subject:  idToken.IDTokenClaims.Subject,
		Email:    idToken.IDTokenClaims.EMail,
		Groups:   groups,
	}, nil
}

func (p Provider) extractUsernameFromToken(idToken idtoken.IDToken) (string, error) {
	switch {
	case p.Conf.OpenVPN.UsernameCEL != "":
		out, _, err := p.celEvalPrg.Eval(map[string]any{
			"oauth2TokenClaims": idToken.IDTokenClaims.Claims,
		})
		if err != nil {
			return "", fmt.Errorf("failed to evaluate CEL expression for username: %w", err)
		}

		username, ok := out.Value().(string)
		if !ok {
			return "", fmt.Errorf("%w: CEL expression for username did not evaluate to a string: %T", types.ErrInvalidClaimType, out.Value())
		}

		return username, nil
	case p.Conf.OpenVPN.UsernameClaim != "":
		usernameClaim, ok := idToken.IDTokenClaims.Claims[p.Conf.OpenVPN.UsernameClaim]
		if !ok {
			return "", fmt.Errorf("%w: %s", types.ErrNonExistsClaim, p.Conf.OpenVPN.UsernameClaim)
		}

		username, ok := usernameClaim.(string)
		if !ok {
			return "", fmt.Errorf("%w: username claim did not evaluate to a string: %T", types.ErrInvalidClaimType, usernameClaim)
		}

		return username, nil
	default:
		return "", nil
	}
}

func (p Provider) extractGroups(ctx context.Context, logger *slog.Logger, tokens idtoken.IDToken) ([]string, error) {
	groupClaim, ok := tokens.IDTokenClaims.Claims[p.Conf.OAuth2.GroupsClaim]
	if !ok {
		logger.LogAttrs(ctx, slog.LevelWarn, "provider did not return a groups claim. validation of groups is not possible.")

		return nil, nil
	}

	if groupClaim == nil {
		return nil, nil
	}

	switch groups := groupClaim.(type) {
	case []string:
		return groups, nil
	case []any:
		var convertedGroups []string

		for _, group := range groups {
			strGroup, ok := group.(string)
			if !ok {
				return nil, fmt.Errorf("%w: groups claim contains non-string element: %T", types.ErrInvalidClaimType, group)
			}

			convertedGroups = append(convertedGroups, strGroup)
		}

		return convertedGroups, nil
	default:
		return nil, fmt.Errorf("%w: groups claim: %T", types.ErrInvalidClaimType, groupClaim)
	}
}
