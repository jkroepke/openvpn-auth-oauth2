package types

import (
	"golang.org/x/oauth2"
)

type UserInfo struct {
	Subject  string
	Email    string
	Username string
	Groups   []string
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
