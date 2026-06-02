package google_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/google"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/test/testsuite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	gooauth2 "golang.org/x/oauth2"
)

func TestValidateGroups(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name           string
		tokenGroups    string
		requiredGroups []string
		err            string
	}{
		{
			"groups not present",
			`{"memberships": [], "nextPageToken": ""}`,
			make([]string, 0),
			"",
		},
		{
			"groups empty",
			`{"memberships": [], "nextPageToken": ""}`,
			make([]string, 0),
			"",
		},
		{
			"groups present",
			`{"memberships": [{"name": "groups/000000000000000/memberships/123456789101112131415", "memberKey": {"id": "user@example.com"}, "roles": [{"name": "MEMBER"}], "preferredMemberKey": {"id": "user@example.com"}}], "nextPageToken": ""}`,
			make([]string, 0),
			"",
		},
		{
			"groups present with nextPageToken",
			`{"memberships": [{"name": "groups/000000000000000/memberships/123456789101112131415", "memberKey": {"id": "user@example.com"}, "roles": [{"name": "MEMBER"}], "preferredMemberKey": {"id": "user@example.com"}}], "nextPageToken": "token"}`,
			make([]string, 0),
			"",
		},
		{
			"configure one group",
			`{"memberships": [{"name": "groups/000000000000000/memberships/123456789101112131415", "memberKey": {"id": "user@example.com"}, "roles": [{"name": "MEMBER"}], "preferredMemberKey": {"id": "user@example.com"}}], "nextPageToken": ""}`,
			[]string{"000000000000000"},
			"",
		},
		{
			"access token is empty",
			`ERROR`,
			[]string{"000000000000000"},
			"access token is empty",
		},
		{
			"invalid json",
			`ERROR`,
			[]string{"000000000000000"},
			"unable to decode JSON from Google API https://cloudidentity.googleapis.com/v1/groups/000000000000000/memberships: 'ERROR': invalid character 'E' looking for beginning of value",
		},
		{
			"got error from API",
			`{"error": {"message": "error"}}`,
			[]string{"000000000000000"},
			"error from Google API https://cloudidentity.googleapis.com/v1/groups/000000000000000/memberships: http status code: 500; message: error",
		},
		{
			"permission denied",
			`{"error": {"message": "Error(4001): Permission denied for membership resource 'groups/000000000000000' (or it may not exist)."}}`,
			[]string{"000000000000000"},
			oauth2.ErrMissingRequiredGroup.Error(),
		},
		{
			"configure two group, none match",
			`{"memberships": [{"name": "groups/000000000000002/memberships/123456789101112131416", "memberKey": {"id": "user@example.com"}, "roles": [{"name": "MEMBER"}], "preferredMemberKey": {"id": "user@example.com"}}], "nextPageToken": ""}`,
			[]string{"000000000000000", "000000000000001"},
			oauth2.ErrMissingRequiredGroup.Error(),
		},
		{
			"configure two group, missing one",
			`{"memberships": [{"name": "groups/000000000000000/memberships/123456789101112131415", "memberKey": {"id": "user@example.com"}, "roles": [{"name": "MEMBER"}], "preferredMemberKey": {"id": "user@example.com"}}], "nextPageToken": ""}`,
			[]string{"000000000000000", "000000000000001"},
			"",
		},
		{
			"configure two group",
			`{"memberships": [{"name": "groups/000000000000000/memberships/123456789101112131415", "memberKey": {"id": "user@example.com"}, "roles": [{"name": "MEMBER"}], "preferredMemberKey": {"id": "user@example.com"}},{"name": "groups/000000000000001/memberships/123456789101112131415", "memberKey": {"id": "user@example.com"}, "roles": [{"name": "MEMBER"}], "preferredMemberKey": {"id": "user@example.com"}}], "nextPageToken": ""}`,
			[]string{"000000000000000", "000000000000001"},
			"",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			token := &oidc.Tokens[*idtoken.Claims]{
				Token: &gooauth2.Token{
					AccessToken: "TOKEN",
				},
				IDTokenClaims: &idtoken.Claims{},
			}

			if tc.name == "access token is empty" {
				token.AccessToken = ""
			}

			conf := config.Config{
				OAuth2: config.OAuth2{
					Validate: config.OAuth2Validate{
						Groups: tc.requiredGroups,
					},
				},
			}

			httpClient := &http.Client{
				Transport: testsuite.NewRoundTripperFunc(nil, func(_ http.RoundTripper, req *http.Request) (*http.Response, error) {
					resp := httptest.NewRecorder()
					if strings.Contains(tc.tokenGroups, "error") {
						resp.WriteHeader(http.StatusInternalServerError)
					}

					if req.URL.Query().Has("pageToken") {
						_, _ = resp.WriteString(`{"memberships": [], "nextPageToken": ""}`)
					} else {
						_, _ = resp.WriteString(tc.tokenGroups)
					}

					return resp.Result(), nil
				}),
			}

			provider, err := google.NewProvider(t.Context(), conf, httpClient)
			require.NoError(t, err)

			err = provider.CheckUser(t.Context(), state.State{}, types.UserInfo{Subject: "123456789101112131415"}, token)

			if tc.err == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}

func TestValidateGroupsTransitive(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name           string
		email          string
		response       string
		statusCode     int
		requiredGroups []string
		err            string
		errContains    string
	}{
		{
			"transitive member",
			"user@example.com",
			`{"hasMembership": true}`,
			http.StatusOK,
			[]string{"000000000000000"},
			"",
			"",
		},
		{
			"not a transitive member",
			"user@example.com",
			`{"hasMembership": false}`,
			http.StatusOK,
			[]string{"000000000000000"},
			oauth2.ErrMissingRequiredGroup.Error(),
			"",
		},
		{
			"permission denied is not a member",
			"user@example.com",
			`{"error": {"message": "Error(4001): Permission denied for membership resource 'groups/000000000000000' (or it may not exist)."}}`,
			http.StatusForbidden,
			[]string{"000000000000000"},
			oauth2.ErrMissingRequiredGroup.Error(),
			"",
		},
		{
			"two groups, first matches transitively",
			"user@example.com",
			`{"hasMembership": true}`,
			http.StatusOK,
			[]string{"000000000000000", "000000000000001"},
			"",
			"",
		},
		{
			// Falls back to the subject as member_key_id when the email is empty.
			"member by subject when email is empty",
			"",
			`{"hasMembership": true}`,
			http.StatusOK,
			[]string{"000000000000000"},
			"",
			"",
		},
		{
			"api error is propagated",
			"user@example.com",
			`{"error": {"message": "internal error"}}`,
			http.StatusInternalServerError,
			[]string{"000000000000000"},
			"",
			"http status code: 500",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			token := &oidc.Tokens[*idtoken.Claims]{
				Token: &gooauth2.Token{
					AccessToken: "TOKEN",
				},
				IDTokenClaims: &idtoken.Claims{},
			}

			conf := config.Config{
				OAuth2: config.OAuth2{
					Validate: config.OAuth2Validate{
						Groups: tc.requiredGroups,
					},
				},
				Provider: config.Provider{
					Google: config.ProviderGoogle{
						Validate: config.ProviderGoogleValidate{
							GroupsTransitive: true,
						},
					},
				},
			}

			httpClient := &http.Client{
				Transport: testsuite.NewRoundTripperFunc(nil, func(_ http.RoundTripper, req *http.Request) (*http.Response, error) {
					resp := httptest.NewRecorder()

					if !strings.HasSuffix(req.URL.Path, ":checkTransitiveMembership") {
						resp.WriteHeader(http.StatusInternalServerError)
						_, _ = resp.WriteString(`{"error": {"message": "unexpected endpoint"}}`)

						return resp.Result(), nil
					}

					if !strings.Contains(req.URL.RawQuery, "member_key_id") {
						resp.WriteHeader(http.StatusBadRequest)
						_, _ = resp.WriteString(`{"error": {"message": "missing member_key_id"}}`)

						return resp.Result(), nil
					}

					if tc.statusCode != 0 && tc.statusCode != http.StatusOK {
						resp.WriteHeader(tc.statusCode)
					}

					_, _ = resp.WriteString(tc.response)

					return resp.Result(), nil
				}),
			}

			provider, err := google.NewProvider(t.Context(), conf, httpClient)
			require.NoError(t, err)

			err = provider.CheckUser(
				t.Context(),
				state.State{},
				types.UserInfo{Subject: "123456789101112131415", Email: tc.email},
				token,
			)

			switch {
			case tc.errContains != "":
				require.ErrorContains(t, err, tc.errContains)
			case tc.err != "":
				require.EqualError(t, err, tc.err)
			default:
				require.NoError(t, err)
			}
		})
	}
}
