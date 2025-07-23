package types

import (
	"golang.org/x/oauth2"
)

type UserInfo struct {
	Subject           string   `json:"sub,omitempty"`
	Email             string   `json:"email,omitempty"`
	PreferredUsername string   `json:"preferred_username,omitempty"`
	Groups            []string `json:"groups,omitempty"`
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
