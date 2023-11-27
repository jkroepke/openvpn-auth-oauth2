package generic_test

import (
	"context"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/generic"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func TestCheckUser(t *testing.T) {
	t.Parallel()

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

	conf := config.Config{
		OAuth2: config.OAuth2{
			Validate: config.OAuth2Validate{},
		},
	}

	provider := generic.NewProvider(conf)

	userData, err := provider.GetUser(context.Background(), token)
	require.NoError(t, err)

	err = provider.CheckUser(context.Background(), state.State{}, userData, token)
	require.NoError(t, err)
}

func TestValidateGroups(t *testing.T) {
	t.Parallel()

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
		{"require one group, claim not present", "", []any{"apple"}, []string{"apple"}, "missing claim: groups"},
		{"require two group, missing one", "groups", []any{"apple"}, []string{"apple", "pear"}, "missing required group: pear"},
		{"require two group", "groups", []any{"apple", "pear"}, []string{"apple", "pear"}, ""},
	} {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			token := &oidc.Tokens[*oidc.IDTokenClaims]{
				IDTokenClaims: &oidc.IDTokenClaims{
					Claims: map[string]any{
						tt.tokenClaim: tt.tokenGroups,
					},
				},
			}

			conf := config.Config{
				OAuth2: config.OAuth2{
					Validate: config.OAuth2Validate{
						Groups: tt.requiredGroups,
					},
				},
			}

			err := generic.NewProvider(conf).CheckGroups(token)

			if tt.err == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Equal(t, tt.err, err.Error())
			}
		})
	}
}

func TestValidateRoles(t *testing.T) {
	t.Parallel()

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
		{"require one group, claim not present", "", []any{"apple"}, []string{"apple"}, "missing claim: roles"},
		{"require two group, missing one", "roles", []any{"apple"}, []string{"apple", "pear"}, "missing required role: pear"},
		{"require two group", "roles", []any{"apple", "pear"}, []string{"apple", "pear"}, ""},
	} {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			token := &oidc.Tokens[*oidc.IDTokenClaims]{
				IDTokenClaims: &oidc.IDTokenClaims{
					Claims: map[string]any{
						tt.tokenClaim: tt.tokenRoles,
					},
				},
			}

			conf := config.Config{
				OAuth2: config.OAuth2{
					Validate: config.OAuth2Validate{
						Roles: tt.requiredRoles,
					},
				},
			}

			err := generic.NewProvider(conf).CheckRoles(token)
			if tt.err == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Equal(t, tt.err, err.Error())
			}
		})
	}
}

func TestValidateCommonName(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name               string
		tokenClaim         string
		tokenCommonName    any
		requiredCommonName string
		commonNameMode     config.OpenVPNCommonNameMode
		err                string
	}{
		{"not require", "", nil, "", config.CommonNameModePlain, ""},
		{"sub empty", "sub", "apple", "", config.CommonNameModePlain, "common_name mismatch: openvpn client is empty"},
		{"sub required", "sub", "apple", "apple", config.CommonNameModePlain, ""},
		{"sub required wrong", "sub", "pear", "apple", config.CommonNameModePlain, "common_name mismatch: openvpn client: apple - oidc token: pear"},
		{"nonexists claim", "nonexists", "pear", "apple", config.CommonNameModePlain, "missing claim: nonexists"},
		{"sub md5", "sub", "apple", utils.TransformCommonName(config.CommonNameModeMD5, "apple"), config.CommonNameModeMD5, ""},
		{"sub sha1", "sub", "apple", utils.TransformCommonName(config.CommonNameModeSHA1, "apple"), config.CommonNameModeSHA1, ""},
		{"sub omit", "sub", "apple", config.CommonNameModeOmitValue, config.CommonNameModeOmit, "common_name mismatch: openvpn client is empty"},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			token := &oidc.Tokens[*oidc.IDTokenClaims]{
				IDTokenClaims: &oidc.IDTokenClaims{
					Claims: map[string]any{
						"sub": tt.tokenCommonName,
					},
				},
			}

			conf := config.Config{
				OpenVpn: config.OpenVpn{
					CommonName: config.OpenVPNCommonName{
						Mode: tt.commonNameMode,
					},
				},
				OAuth2: config.OAuth2{
					Validate: config.OAuth2Validate{
						CommonName: tt.tokenClaim,
					},
				},
			}

			session := state.State{
				CommonName: tt.requiredCommonName,
			}

			err := generic.NewProvider(conf).CheckCommonName(session, token)
			if tt.err == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Equal(t, tt.err, err.Error())
			}
		})
	}
}

func TestValidateIpAddr(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name           string
		validateIPAddr bool
		tokenClaim     string
		tokenIPAddr    any
		requiredIPAddr string
		err            string
	}{
		{"no require", false, "nonexists", "apple", "", ""},
		{"ip present", true, "ipaddr", "apple", "", "ipaddr mismatch: openvpn client: apple - oidc token: "},
		{"sub required", true, "ipaddr", "apple", "apple", ""},
		{"sub required wrong", true, "ipaddr", "pear", "apple", "ipaddr mismatch: openvpn client: pear - oidc token: apple"},
		{"nonexists claim", true, "nonexists", "pear", "apple", "missing claim: ipaddr"},
	} {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			token := &oidc.Tokens[*oidc.IDTokenClaims]{
				IDTokenClaims: &oidc.IDTokenClaims{
					Claims: map[string]any{
						tt.tokenClaim: tt.tokenIPAddr,
					},
				},
			}

			conf := config.Config{
				OAuth2: config.OAuth2{
					Validate: config.OAuth2Validate{
						IPAddr: tt.validateIPAddr,
					},
				},
			}

			session := state.State{
				Ipaddr: tt.requiredIPAddr,
			}

			err := generic.NewProvider(conf).CheckIPAddress(session, token)
			if tt.err == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Equal(t, tt.err, err.Error())
			}
		})
	}
}
