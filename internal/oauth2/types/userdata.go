package types

import (
	"golang.org/x/oauth2"
)

type UserData struct {
	Subject           string
	Email             string
	PreferredUsername string
}

type ProviderConfig struct {
	oauth2.Endpoint
	AuthCodeOptions []oauth2.AuthCodeOption
	Scopes          []string
}

type CtxNonce struct{}
