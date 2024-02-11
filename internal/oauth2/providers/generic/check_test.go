package generic_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/generic"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func TestCheckUser(t *testing.T) {
	t.Parallel()

	token := &oidc.Tokens[*idtoken.Claims]{
		IDTokenClaims: &idtoken.Claims{
			TokenClaims: oidc.TokenClaims{
				Subject: "subnect",
			},
			PreferredUsername: "username",
		},
	}

	conf := config.Config{
		OAuth2: config.OAuth2{
			Validate: config.OAuth2Validate{},
		},
	}

	provider, err := generic.NewProvider(context.Background(), conf, http.DefaultClient)
	require.NoError(t, err)

	userData, err := provider.GetUser(context.Background(), token)
	require.NoError(t, err)

	err = provider.CheckUser(context.Background(), state.State{}, userData, token)
	require.NoError(t, err)
}

func TestValidateGroups(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name           string
		tokenGroups    []string
		requiredGroups []string
		err            string
	}{
		{"groups not present", nil, []string{}, ""},
		{"groups empty", []string{}, []string{}, ""},
		{"groups present", []string{"apple"}, []string{}, ""},
		{"configure one group", []string{"apple"}, []string{"apple"}, ""},
		{"configure two group, none match", []string{}, []string{"apple", "pear"}, generic.ErrMissingRequiredGroup.Error()},
		{"configure two group, missing one", []string{"apple"}, []string{"apple", "pear"}, "missing required group: pear"},
		{"configure two group", []string{"apple", "pear"}, []string{"apple", "pear"}, ""},
	} {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			token := &oidc.Tokens[*idtoken.Claims]{
				IDTokenClaims: &idtoken.Claims{
					Groups: tt.tokenGroups,
				},
			}

			conf := config.Config{
				OAuth2: config.OAuth2{
					Validate: config.OAuth2Validate{
						Groups: tt.requiredGroups,
					},
				},
			}

			provider, err := generic.NewProvider(context.Background(), conf, http.DefaultClient)
			require.NoError(t, err)

			err = provider.CheckGroups(token)

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
		tokenRoles    []string
		requiredRoles []string
		err           string
	}{
		{"groups not present", nil, []string{}, ""},
		{"groups empty", []string{}, []string{}, ""},
		{"groups present", []string{"apple"}, []string{}, ""},
		{"configure one group", []string{"apple"}, []string{"apple"}, ""},
		{"configure two role, none match", []string{}, []string{"apple", "pear"}, generic.ErrMissingRequiredRole.Error()},
		{"configure two group, missing one", []string{"apple"}, []string{"apple", "pear"}, "missing required role: pear"},
		{"configure two group", []string{"apple", "pear"}, []string{"apple", "pear"}, ""},
	} {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			token := &oidc.Tokens[*idtoken.Claims]{
				IDTokenClaims: &idtoken.Claims{
					Roles: tt.tokenRoles,
				},
			}

			conf := config.Config{
				OAuth2: config.OAuth2{
					Validate: config.OAuth2Validate{
						Roles: tt.requiredRoles,
					},
				},
			}

			provider, err := generic.NewProvider(context.Background(), conf, http.DefaultClient)
			require.NoError(t, err)

			err = provider.CheckRoles(token)
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
		tokenCommonName    string
		requiredCommonName string
		commonNameMode     config.OpenVPNCommonNameMode
		err                string
	}{
		{"sub empty", "sub", "apple", "", config.CommonNameModePlain, "common_name mismatch: openvpn client is empty"},
		{"sub required", "sub", "apple", "apple", config.CommonNameModePlain, ""},
		{"sub required wrong", "sub", "pear", "apple", config.CommonNameModePlain, "common_name mismatch: openvpn client: apple - oidc token: pear"},
		{"nonexists claim", "nonexists", "pear", "apple", config.CommonNameModePlain, "missing claim: nonexists"},
		{"sub omit", "sub", "apple", config.CommonNameModeOmitValue, config.CommonNameModeOmit, "common_name mismatch: openvpn client is empty"},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			token := &oidc.Tokens[*idtoken.Claims]{
				IDTokenClaims: &idtoken.Claims{
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

			provider, err := generic.NewProvider(context.Background(), conf, http.DefaultClient)
			require.NoError(t, err)

			err = provider.CheckCommonName(session, token)
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
		setClaim       bool
		tokenIPAddr    string
		requiredIPAddr string
		err            string
	}{
		{"no require", false, false, "apple", "", ""},
		{"ip present", true, true, "apple", "", "ipaddr mismatch: openvpn client: apple - oidc token: "},
		{"sub required", true, true, "apple", "apple", ""},
		{"sub required wrong", true, true, "pear", "apple", "ipaddr mismatch: openvpn client: pear - oidc token: apple"},
		{"nonexists claim", true, false, "pear", "apple", "missing claim: ipaddr"},
	} {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			token := &oidc.Tokens[*idtoken.Claims]{
				IDTokenClaims: &idtoken.Claims{},
			}

			if tt.setClaim {
				token.IDTokenClaims.IPAddr = tt.tokenIPAddr
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

			provider, err := generic.NewProvider(context.Background(), conf, http.DefaultClient)
			require.NoError(t, err)

			err = provider.CheckIPAddress(session, token)
			if tt.err == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Equal(t, tt.err, err.Error())
			}
		})
	}
}
