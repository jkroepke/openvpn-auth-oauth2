package idtoken

import (
	"encoding/json"
	"fmt"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

//nolint:tagliatelle
type Claims struct {
	oidc.TokenClaims
	PreferredUsername string `json:"preferred_username,omitempty"`
	AccessTokenHash   string `json:"at_hash,omitempty"`
	IPAddr            string `json:"ipaddr,omitempty"`
	EMail             string `json:"email,omitempty"`

	Groups []string `json:"groups,omitempty"`
	Roles  []string `json:"roles,omitempty"`

	// https://developers.google.com/identity/openid-connect/openid-connect#hd-param
	Hd string `json:"hd,omitempty"`

	Claims map[string]any `json:"-"`
}

// GetAccessTokenHash implements the oidc.IDTokenClaims interface.
func (c *Claims) GetAccessTokenHash() string {
	return c.AccessTokenHash
}

type cAlias Claims

func (c *Claims) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, (*cAlias)(c)); err != nil {
		return fmt.Errorf("claims: %w into %T", err, c)
	}

	if err := json.Unmarshal(data, &c.Claims); err != nil {
		return fmt.Errorf("claims: %w into %T", err, &c.Claims)
	}

	return nil
}
