package github

import (
	"context"
	"strconv"

	"github.com/jkroepke/openvpn-auth-oauth2/pkg/internal/types"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// user holds GitHub user information as defined by
// https://developer.github.com/v3/users/#response-with-public-profile-information
type userType struct {
	Name  string `json:"name"`
	Login string `json:"login"`
	ID    int    `json:"id"`
	Email string `json:"email"`
}

func (p *Provider) GetUser(ctx context.Context, tokens *oidc.Tokens[*oidc.IDTokenClaims]) (types.UserData, error) {
	var user userType

	_, err := get[userType](ctx, tokens.AccessToken, "https://api.github.com/user", &user)
	if err != nil {
		return types.UserData{}, err
	}

	return types.UserData{
		PreferredUsername: user.Login,
		Subject:           strconv.Itoa(user.ID),
	}, nil
}
