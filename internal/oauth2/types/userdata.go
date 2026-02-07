package types

import (
	"golang.org/x/oauth2"
)

type UserInfo struct {
	Subject  string   `json:"sub"`
	Email    string   `json:"email"`
	Username string   `json:"preferred_username"` //nolint:tagliatelle // preferred_username is the standard claim for the username.
	Groups   []string `json:"groups"`
}

func (u UserInfo) GetSubject() string {
	return u.Subject
}

type ProviderConfig struct {
	oauth2.Endpoint

	AuthCodeOptions []oauth2.AuthCodeOption
	Scopes          []string
}

type CtxNonce struct{}
