package github

import (
	"context"
	"errors"
	"log/slog"
	"strconv"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// user holds GitHub user information as defined by
// https://developer.github.com/v3/users/#response-with-public-profile-information
type userType struct {
	Name  string `json:"name"`
	Login string `json:"login"`
	Email string `json:"email"`
	ID    int    `json:"id"`
}

func (p Provider) GetUser(ctx context.Context, _ *slog.Logger, tokens *oidc.Tokens[*idtoken.Claims]) (types.UserData, error) {
	if tokens.AccessToken == "" {
		return types.UserData{}, errors.New("access token is empty")
	}

	var user userType

	_, err := get[userType](ctx, p.httpClient, tokens.AccessToken, "https://api.github.com/user", &user)
	if err != nil {
		return types.UserData{}, err
	}

	return types.UserData{
		PreferredUsername: user.Login,
		Email:             user.Email,
		Subject:           strconv.Itoa(user.ID),
	}, nil
}
