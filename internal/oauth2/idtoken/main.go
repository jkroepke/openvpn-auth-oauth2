package idtoken

import "github.com/zitadel/oidc/v3/pkg/oidc"

//nolint:tagliatelle
type Claims struct {
	oidc.TokenClaims
	PreferredUsername string         `json:"preferred_username,omitempty"`
	AccessTokenHash   string         `json:"at_hash,omitempty"`
	IPAddr            string         `json:"ipaddr,omitempty"`
	Claims            map[string]any `json:"-"`
}

// GetAccessTokenHash implements the oidc.IDTokenClaims interface.
func (c *Claims) GetAccessTokenHash() string {
	return c.AccessTokenHash
}
