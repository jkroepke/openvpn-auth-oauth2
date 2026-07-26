package github

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/types"
)

// user holds GitHub user information as defined by
// https://developer.github.com/v3/users/#response-with-public-profile-information
type userType struct {
	Name  string `json:"name"`
	Login string `json:"login"`
	Email string `json:"email"`
	ID    int    `json:"id"`
}

// GetUser fetches the authenticated GitHub user through the REST API.
func (p Provider) GetUser(ctx context.Context, _ *slog.Logger, tokens *idtoken.IDToken, _ *types.UserInfo) (types.UserInfo, error) {
	if tokens.AccessToken == "" {
		return types.UserInfo{}, errors.New("access token is empty")
	}

	var user userType

	_, err := get[userType](ctx, p.httpClient, tokens.AccessToken, "https://api.github.com/user", &user)
	if err != nil {
		return types.UserInfo{}, err
	}

	userInfo := types.UserInfo{
		Username: user.Login,
		Email:    user.Email,
		Subject:  strconv.Itoa(user.ID),
	}

	organizations, err := p.getOrganizations(ctx, tokens)
	if err != nil {
		return types.UserInfo{}, fmt.Errorf("error getting GitHub organizations: %w", err)
	}

	userInfo.Groups = organizations

	teams, err := p.getTeams(ctx, tokens)
	if err != nil {
		return types.UserInfo{}, fmt.Errorf("error getting GitHub teams: %w", err)
	}

	userInfo.Roles = teams

	return userInfo, nil
}
