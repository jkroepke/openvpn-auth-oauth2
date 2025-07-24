package idtoken

import (
	"encoding/json"
	"fmt"

	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type IDToken = *oidc.Tokens[*Claims]

//nolint:tagliatelle
type Claims struct {
	oidc.TokenClaims

	Claims map[string]any `json:"-"`

	PreferredUsername string   `json:"preferred_username,omitempty"`
	AccessTokenHash   string   `json:"at_hash,omitempty"`
	IPAddr            string   `json:"ipaddr,omitempty"`
	EMail             string   `json:"email,omitempty"`
	Hd                string   `json:"hd,omitempty"`
	Roles             []string `json:"roles,omitempty"`
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
