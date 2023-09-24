package oidc

import (
	"context"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/stretchr/testify/assert"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/zitadel/oidc/v2/pkg/oidc"
)

func TestCheckUser(t *testing.T) {
	token := &oidc.Tokens[*oidc.IDTokenClaims]{
		IDTokenClaims: &oidc.IDTokenClaims{
			TokenClaims: oidc.TokenClaims{
				Subject: "subnect",
			},
			UserInfoProfile: oidc.UserInfoProfile{
				PreferredUsername: "username",
			},
			Claims: map[string]any{},
		},
	}

	conf := &config.Config{
		Oauth2: &config.OAuth2{
			Validate: &config.OAuth2Validate{},
		},
	}

	provider := NewProvider(conf)

	userData, err := provider.GetUser(context.Background(), token)
	assert.NoError(t, err)

	err = provider.CheckUser(context.Background(), &state.State{}, userData, token)
	assert.NoError(t, err)
}

func TestValidateGroups(t *testing.T) {
	for _, tt := range []struct {
		name           string
		tokenClaim     string
		tokenGroups    any
		requiredGroups []string
		err            string
	}{
		{"claim not present", "", nil, []string{}, ""},
		{"groups not present", "groups", nil, []string{}, ""},
		{"groups empty", "groups", []any{}, []string{}, ""},
		{"groups present", "groups", []any{"apple"}, []string{}, ""},
		{"require one group", "groups", []any{"apple"}, []string{"apple"}, ""},
		{"require one group, claim not present", "", []any{"apple"}, []string{"apple"}, "missing groups claim"},
		{"require two group, missing one", "groups", []any{"apple"}, []string{"apple", "pear"}, "missing required group pear"},
		{"require two group", "groups", []any{"apple", "pear"}, []string{"apple", "pear"}, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			token := &oidc.Tokens[*oidc.IDTokenClaims]{
				IDTokenClaims: &oidc.IDTokenClaims{
					Claims: map[string]any{
						tt.tokenClaim: tt.tokenGroups,
					},
				},
			}

			conf := &config.Config{
				Oauth2: &config.OAuth2{
					Validate: &config.OAuth2Validate{
						Groups: tt.requiredGroups,
					},
				},
			}

			err := NewProvider(conf).CheckGroups(token)

			if tt.err == "" {
				assert.NoError(t, err)
			} else {
				assert.Equal(t, err.Error(), tt.err)
			}
		})
	}
}

func TestValidateRoles(t *testing.T) {
	for _, tt := range []struct {
		name          string
		tokenClaim    string
		tokenRoles    any
		requiredRoles []string
		err           string
	}{
		{"claim not present", "", nil, []string{}, ""},
		{"groups not present", "roles", nil, []string{}, ""},
		{"groups empty", "roles", []any{}, []string{}, ""},
		{"groups present", "roles", []any{"apple"}, []string{}, ""},
		{"require one group", "roles", []any{"apple"}, []string{"apple"}, ""},
		{"require one group, claim not present", "", []any{"apple"}, []string{"apple"}, "missing roles claim"},
		{"require two group, missing one", "roles", []any{"apple"}, []string{"apple", "pear"}, "missing required role pear"},
		{"require two group", "roles", []any{"apple", "pear"}, []string{"apple", "pear"}, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			token := &oidc.Tokens[*oidc.IDTokenClaims]{
				IDTokenClaims: &oidc.IDTokenClaims{
					Claims: map[string]any{
						tt.tokenClaim: tt.tokenRoles,
					},
				},
			}

			conf := &config.Config{
				Oauth2: &config.OAuth2{
					Validate: &config.OAuth2Validate{
						Roles: tt.requiredRoles,
					},
				},
			}

			err := NewProvider(conf).CheckRoles(token)
			if tt.err == "" {
				assert.NoError(t, err)
			} else {
				assert.Equal(t, err.Error(), tt.err)
			}
		})
	}
}

func TestValidateCommonName(t *testing.T) {
	for _, tt := range []struct {
		name               string
		tokenClaim         string
		tokenCommonName    any
		requiredCommonName string
		err                string
	}{
		{"not require", "", nil, "", ""},
		{"sub present", "sub", "apple", "", "common_name mismatch: openvpn client: apple - oidc token: "},
		{"sub required", "sub", "apple", "apple", ""},
		{"sub required wrong", "sub", "pear", "apple", "common_name mismatch: openvpn client: pear - oidc token: apple"},
		{"nonexists claim", "nonexists", "pear", "apple", "missing nonexists claim"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			token := &oidc.Tokens[*oidc.IDTokenClaims]{
				IDTokenClaims: &oidc.IDTokenClaims{
					Claims: map[string]any{
						"sub": tt.tokenCommonName,
					},
				},
			}

			conf := &config.Config{
				Oauth2: &config.OAuth2{
					Validate: &config.OAuth2Validate{
						CommonName: tt.tokenClaim,
					},
				},
			}

			session := &state.State{
				CommonName: tt.requiredCommonName,
			}

			err := NewProvider(conf).CheckCommonName(session, token)
			if tt.err == "" {
				assert.NoError(t, err)
			} else {
				assert.Equal(t, err.Error(), tt.err)
			}
		})
	}
}

func TestValidateIpAddr(t *testing.T) {
	for _, tt := range []struct {
		name           string
		validateIpAddr bool
		tokenClaim     string
		tokenIpAddr    any
		requiredIpAddr string
		err            string
	}{
		{"no require", false, "nonexists", "apple", "", ""},
		{"ip present", true, "ipaddr", "apple", "", "ipaddr mismatch: openvpn client: apple - oidc token: "},
		{"sub required", true, "ipaddr", "apple", "apple", ""},
		{"sub required wrong", true, "ipaddr", "pear", "apple", "ipaddr mismatch: openvpn client: pear - oidc token: apple"},
		{"nonexists claim", true, "nonexists", "pear", "apple", "missing ipaddr claim"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			token := &oidc.Tokens[*oidc.IDTokenClaims]{
				IDTokenClaims: &oidc.IDTokenClaims{
					Claims: map[string]any{
						tt.tokenClaim: tt.tokenIpAddr,
					},
				},
			}

			conf := &config.Config{
				Oauth2: &config.OAuth2{
					Validate: &config.OAuth2Validate{
						IpAddr: tt.validateIpAddr,
					},
				},
			}

			session := &state.State{
				Ipaddr: tt.requiredIpAddr,
			}

			err := NewProvider(conf).CheckIpAddress(session, token)
			if tt.err == "" {
				assert.NoError(t, err)
			} else {
				assert.Equal(t, err.Error(), tt.err)
			}
		})
	}
}
