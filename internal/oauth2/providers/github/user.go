package github

import (
	"context"
	"strconv"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/types"
	"github.com/zitadel/oidc/v2/pkg/oidc"
)

// user holds GitHub user information as defined by
// https://developer.github.com/v3/users/#response-with-public-profile-information
type userType struct {
	Name  string `json:"name"`
	Login string `json:"login"`
	ID    int    `json:"id"`
	Email string `json:"email"`
}

func (p *Provider) GetUser(ctx context.Context, tokens *oidc.Tokens[*oidc.IDTokenClaims]) (*types.UserData, error) {
	var u userType

	_, err := get[userType](ctx, tokens.AccessToken, "https://api.github.com/user", &u)
	if err != nil {
		return nil, err
	}

	return &types.UserData{
		PreferredUsername: u.Login,
		Subject:           strconv.Itoa(u.ID),
	}, nil
}
