package generic_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/generic"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils/testutils"
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

	userData, err := provider.GetUser(context.Background(), testutils.NewTestLogger().Logger, token)
	require.NoError(t, err)

	err = provider.CheckUser(context.Background(), state.State{}, userData, token)
	require.NoError(t, err)
}

func TestInvalidToken(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name  string
		conf  config.Config
		token *oidc.Tokens[*idtoken.Claims]
		err   error
	}{
		{
			"nil without validation",
			config.Config{
				OAuth2: config.OAuth2{
					Validate: config.OAuth2Validate{},
				},
			},
			&oidc.Tokens[*idtoken.Claims]{
				IDTokenClaims: nil,
			},
			nil,
		},
		{
			"nil with group",
			config.Config{
				OAuth2: config.OAuth2{
					Validate: config.OAuth2Validate{
						Groups: []string{"apple"},
					},
				},
			},
			&oidc.Tokens[*idtoken.Claims]{
				IDTokenClaims: nil,
			},
			generic.ErrMissingClaim,
		},
		{
			"nil with roles",
			config.Config{
				OAuth2: config.OAuth2{
					Validate: config.OAuth2Validate{
						Roles: []string{"apple"},
					},
				},
			},
			&oidc.Tokens[*idtoken.Claims]{
				IDTokenClaims: nil,
			},
			generic.ErrMissingClaim,
		},
		{
			"nil with username",
			config.Config{
				OAuth2: config.OAuth2{
					Validate: config.OAuth2Validate{
						CommonName: "sub",
					},
				},
			},
			&oidc.Tokens[*idtoken.Claims]{
				IDTokenClaims: nil,
			},
			generic.ErrMissingClaim,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			provider, err := generic.NewProvider(context.Background(), tt.conf, http.DefaultClient)
			require.NoError(t, err)

			userData, err := provider.GetUser(context.Background(), testutils.NewTestLogger().Logger, tt.token)
			require.NoError(t, err)

			err = provider.CheckUser(context.Background(), state.State{CommonName: "user"}, userData, tt.token)
			if tt.err == nil {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.ErrorIs(t, err, tt.err)
			}
		})
	}
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
		{"configure one group, groups not present", nil, []string{"apple"}, "missing claim: groups"},
		{"configure two group, none match", []string{}, []string{"apple", "pear"}, generic.ErrMissingRequiredGroup.Error()},
		{"configure two group, missing one", []string{"apple"}, []string{"apple", "pear"}, ""},
		{"configure two group", []string{"apple", "pear"}, []string{"apple", "pear"}, ""},
	} {
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
		{"configure one role", []string{"apple"}, []string{"apple"}, ""},
		{"configure one role, role not present", nil, []string{"apple"}, "missing claim: roles"},
		{"configure two role, none match", []string{}, []string{"apple", "pear"}, generic.ErrMissingRequiredRole.Error()},
		{"configure two role, missing one", []string{"apple"}, []string{"apple", "pear"}, ""},
		{"configure two role", []string{"apple", "pear"}, []string{"apple", "pear"}, ""},
	} {
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
		tokenCommonName    string
		requiredCommonName string
		conf               config.Config
		err                error
	}{
		{
			"sub empty",
			"apple",
			"",
			config.Config{
				OpenVpn: config.OpenVpn{
					CommonName: config.OpenVPNCommonName{
						Mode: config.CommonNameModePlain,
					},
				},
				OAuth2: config.OAuth2{
					Validate: config.OAuth2Validate{
						CommonName: "sub",
					},
				},
			},
			errors.New("common_name mismatch: openvpn client is empty"),
		},
		{
			"sub required",
			"apple",
			"apple",
			config.Config{
				OpenVpn: config.OpenVpn{
					CommonName: config.OpenVPNCommonName{
						Mode: config.CommonNameModePlain,
					},
				},
				OAuth2: config.OAuth2{
					Validate: config.OAuth2Validate{
						CommonName: "sub",
					},
				},
			},
			nil,
		},
		{
			"sub required case insensitive",
			"APPLE",
			"apple",
			config.Config{
				OpenVpn: config.OpenVpn{
					CommonName: config.OpenVPNCommonName{
						Mode: config.CommonNameModePlain,
					},
				},
				OAuth2: config.OAuth2{
					Validate: config.OAuth2Validate{
						CommonName:              "sub",
						CommonNameCaseSensitive: false,
					},
				},
			},
			nil,
		},
		{
			"sub required wrong case insensitive",
			"APPLE",
			"apple",
			config.Config{
				OpenVpn: config.OpenVpn{
					CommonName: config.OpenVPNCommonName{
						Mode: config.CommonNameModePlain,
					},
				},
				OAuth2: config.OAuth2{
					Validate: config.OAuth2Validate{
						CommonName:              "sub",
						CommonNameCaseSensitive: true,
					},
				},
			},
			errors.New("common_name mismatch: openvpn client: apple - oidc token: APPLE"),
		},
		{
			"sub required wrong",
			"pear",
			"apple",
			config.Config{
				OpenVpn: config.OpenVpn{
					CommonName: config.OpenVPNCommonName{
						Mode: config.CommonNameModePlain,
					},
				},
				OAuth2: config.OAuth2{
					Validate: config.OAuth2Validate{
						CommonName: "sub",
					},
				},
			},
			errors.New("common_name mismatch: openvpn client: apple - oidc token: pear"),
		},
		{
			"nonexists claim",
			"pear",
			"apple",
			config.Config{
				OpenVpn: config.OpenVpn{
					CommonName: config.OpenVPNCommonName{
						Mode: config.CommonNameModePlain,
					},
				},
				OAuth2: config.OAuth2{
					Validate: config.OAuth2Validate{
						CommonName: "nonexists",
					},
				},
			},
			errors.New("missing claim: nonexists"),
		},
		{
			"sub omit",
			"apple",
			config.CommonNameModeOmitValue,
			config.Config{
				OpenVpn: config.OpenVpn{
					CommonName: config.OpenVPNCommonName{
						Mode: config.CommonNameModeOmit,
					},
				},
				OAuth2: config.OAuth2{
					Validate: config.OAuth2Validate{
						CommonName: "sub",
					},
				},
			},
			errors.New("common_name mismatch: openvpn client is empty"),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			token := &oidc.Tokens[*idtoken.Claims]{
				IDTokenClaims: &idtoken.Claims{
					Claims: map[string]any{
						"sub": tt.tokenCommonName,
					},
				},
			}

			session := state.State{
				CommonName: tt.requiredCommonName,
			}

			provider, err := generic.NewProvider(context.Background(), tt.conf, http.DefaultClient)
			require.NoError(t, err)

			err = provider.CheckCommonName(session, token)
			if tt.err == nil {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.EqualError(t, tt.err, err.Error())
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
				IPAddr: tt.requiredIPAddr,
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
