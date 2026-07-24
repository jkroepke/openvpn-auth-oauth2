package generic

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/types"
)

// GetUser normalizes user data from UserInfo and ID token claims.
func (p Provider) GetUser(ctx context.Context, logger *slog.Logger, tokens *idtoken.IDToken, userinfo *types.UserInfo) (types.UserInfo, error) {
	user := userFromUserInfo(userinfo)

	if tokens == nil {
		return user, nil
	}

	if tokens.IDTokenClaims == nil {
		if userinfo == nil {
			logMissingIDToken(ctx, logger, tokens)
		}

		return user, nil
	}

	fillUserFromIDToken(&user, tokens.IDTokenClaims)

	if err := p.fillUserGroupsAndRoles(ctx, logger, tokens, &user); err != nil {
		return types.UserInfo{}, err
	}

	return user, nil
}

func userFromUserInfo(userinfo *types.UserInfo) types.UserInfo {
	if userinfo != nil {
		return *userinfo
	}

	return types.UserInfo{}
}

func fillUserFromIDToken(user *types.UserInfo, claims *idtoken.Claims) {
	if user.Subject == "" {
		user.Subject = claims.Subject
	}

	if user.Email == "" {
		user.Email = claims.EMail
	}

	if user.Username == "" {
		user.Username = claims.PreferredUsername
	}
}

func (p Provider) fillUserGroupsAndRoles(
	ctx context.Context,
	logger *slog.Logger,
	tokens *idtoken.IDToken,
	user *types.UserInfo,
) error {
	if user.Groups == nil {
		groups, err := p.extractStringSliceClaim(
			ctx,
			logger,
			tokens,
			p.Conf.OAuth2.GroupsClaim,
			len(p.Conf.OAuth2.Validate.Groups) != 0,
		)
		if err != nil {
			return err
		}

		user.Groups = groups
	}

	if user.Roles == nil {
		roles, err := p.extractStringSliceClaim(ctx, logger, tokens, "roles", false)
		if err != nil {
			return err
		}

		user.Roles = roles
	}

	return nil
}

func logMissingIDToken(ctx context.Context, logger *slog.Logger, tokens *idtoken.IDToken) {
	if tokens.IDToken == "" {
		// if tokens.Token.Extra("id_token") != nil {
		// 	logger.Warn("The provider has returned an 'id_token', however, it was configured as an OAUTH2 provider. " +
		// 		"As a result, user data validation cannot be performed. If you have defined endpoints in the configuration, please remove them and retry.")
		// 	logger.Debug("id_token", "id_token", tokens.Token.Extra("id_token"))
		// } else {
		logger.LogAttrs(ctx, slog.LevelWarn, "provider did not return a id_token. validation of user data is not possible.")

		return
	}

	logger.LogAttrs(ctx, slog.LevelWarn, "provider did return a id_token, but it was not parsed correctly. Validation of user data is not possible."+
		" Enable DEBUG logs to see the raw token and report this to maintainer.")
	logger.LogAttrs(
		ctx, slog.LevelDebug, "id_token",
		slog.String("id_token", tokens.IDToken),
	)
}

// extractStringSliceClaim reads a string-list claim from the ID token.
func (p Provider) extractStringSliceClaim(
	ctx context.Context,
	logger *slog.Logger,
	tokens *idtoken.IDToken,
	claimName string,
	warnIfMissing bool,
) ([]string, error) {
	claim, ok := tokens.IDTokenClaims.Claims[claimName]
	if !ok {
		if warnIfMissing {
			logger.LogAttrs(ctx, slog.LevelWarn, "provider did not return a groups claim. validation of groups is not possible.")
		}

		return nil, nil
	}

	if claim == nil {
		return nil, nil
	}

	switch values := claim.(type) {
	case []string:
		return values, nil
	case []any:
		convertedValues := make([]string, 0, len(values))

		for _, value := range values {
			stringValue, ok := value.(string)
			if !ok {
				return nil, fmt.Errorf("%w: %s claim contains non-string element: %T", types.ErrInvalidClaimType, claimName, value)
			}

			convertedValues = append(convertedValues, stringValue)
		}

		return convertedValues, nil
	default:
		return nil, fmt.Errorf("%w: %s claim: %T", types.ErrInvalidClaimType, claimName, claim)
	}
}
