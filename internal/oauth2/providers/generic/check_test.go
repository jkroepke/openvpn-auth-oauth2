package generic_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
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

	provider, err := generic.NewProvider(t.Context(), conf, http.DefaultClient)
	require.NoError(t, err)

	userData, err := provider.GetUser(t.Context(), testutils.NewTestLogger().Logger, token)
	require.NoError(t, err)

	err = provider.CheckUser(t.Context(), state.State{}, userData, token)
	require.NoError(t, err)
}

func TestInvalidToken(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
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
			oauth2.ErrMissingClaim,
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
			oauth2.ErrMissingClaim,
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
			oauth2.ErrMissingClaim,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			provider, err := generic.NewProvider(t.Context(), tc.conf, http.DefaultClient)
			require.NoError(t, err)

			userData, err := provider.GetUser(t.Context(), testutils.NewTestLogger().Logger, tc.token)
			require.NoError(t, err)

			err = provider.CheckUser(t.Context(), state.State{Client: state.ClientIdentifier{CommonName: "user"}}, userData, tc.token)
			if tc.err == nil {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.ErrorIs(t, err, tc.err)
			}
		})
	}
}

func TestValidateGroups(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name           string
		tokenGroups    []string
		requiredGroups []string
		err            string
	}{
		{"groups not present", nil, make([]string, 0), ""},
		{"groups empty", make([]string, 0), make([]string, 0), ""},
		{"groups present", []string{"apple"}, make([]string, 0), ""},
		{"configure one group", []string{"apple"}, []string{"apple"}, ""},
		{"configure one group, groups not present", nil, []string{"apple"}, "missing claim: groups"},
		{"configure two group, none match", make([]string, 0), []string{"apple", "pear"}, oauth2.ErrMissingRequiredGroup.Error()},
		{"configure two group, missing one", []string{"apple"}, []string{"apple", "pear"}, ""},
		{"configure two group", []string{"apple", "pear"}, []string{"apple", "pear"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			token := &oidc.Tokens[*idtoken.Claims]{
				IDTokenClaims: &idtoken.Claims{
					Groups: tc.tokenGroups,
				},
			}

			conf := config.Config{
				OAuth2: config.OAuth2{
					Validate: config.OAuth2Validate{
						Groups: tc.requiredGroups,
					},
				},
			}

			provider, err := generic.NewProvider(t.Context(), conf, http.DefaultClient)
			require.NoError(t, err)

			err = provider.CheckGroups(token)

			if tc.err == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Equal(t, tc.err, err.Error())
			}
		})
	}
}

func TestValidateRoles(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name          string
		tokenRoles    []string
		requiredRoles []string
		err           string
	}{
		{"groups not present", nil, make([]string, 0), ""},
		{"groups empty", make([]string, 0), make([]string, 0), ""},
		{"groups present", []string{"apple"}, make([]string, 0), ""},
		{"configure one role", []string{"apple"}, []string{"apple"}, ""},
		{"configure one role, role not present", nil, []string{"apple"}, "missing claim: roles"},
		{"configure two role, none match", make([]string, 0), []string{"apple", "pear"}, oauth2.ErrMissingRequiredRole.Error()},
		{"configure two role, missing one", []string{"apple"}, []string{"apple", "pear"}, ""},
		{"configure two role", []string{"apple", "pear"}, []string{"apple", "pear"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			token := &oidc.Tokens[*idtoken.Claims]{
				IDTokenClaims: &idtoken.Claims{
					Roles: tc.tokenRoles,
				},
			}

			conf := config.Config{
				OAuth2: config.OAuth2{
					Validate: config.OAuth2Validate{
						Roles: tc.requiredRoles,
					},
				},
			}

			provider, err := generic.NewProvider(t.Context(), conf, http.DefaultClient)
			require.NoError(t, err)

			err = provider.CheckRoles(token)
			if tc.err == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Equal(t, tc.err, err.Error())
			}
		})
	}
}

func TestValidateCommonName(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
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
				OpenVPN: config.OpenVPN{
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
				OpenVPN: config.OpenVPN{
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
				OpenVPN: config.OpenVPN{
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
				OpenVPN: config.OpenVPN{
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
				OpenVPN: config.OpenVPN{
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
				OpenVPN: config.OpenVPN{
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
				OpenVPN: config.OpenVPN{
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
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			token := &oidc.Tokens[*idtoken.Claims]{
				IDTokenClaims: &idtoken.Claims{
					Claims: map[string]any{
						"sub": tc.tokenCommonName,
					},
				},
			}

			session := state.State{
				Client: state.ClientIdentifier{CommonName: tc.requiredCommonName},
			}

			provider, err := generic.NewProvider(t.Context(), tc.conf, http.DefaultClient)
			require.NoError(t, err)

			err = provider.CheckCommonName(session, token)
			if tc.err == nil {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.EqualError(t, tc.err, err.Error())
			}
		})
	}
}

func TestValidateIpAddr(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
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
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			token := &oidc.Tokens[*idtoken.Claims]{
				IDTokenClaims: &idtoken.Claims{},
			}

			if tc.setClaim {
				token.IDTokenClaims.IPAddr = tc.tokenIPAddr
			}

			conf := config.Config{
				OAuth2: config.OAuth2{
					Validate: config.OAuth2Validate{
						IPAddr: tc.validateIPAddr,
					},
				},
			}

			session := state.State{
				IPAddr: tc.requiredIPAddr,
			}

			provider, err := generic.NewProvider(t.Context(), conf, http.DefaultClient)
			require.NoError(t, err)

			err = provider.CheckIPAddress(session, token)
			if tc.err == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Equal(t, tc.err, err.Error())
			}
		})
	}
}
