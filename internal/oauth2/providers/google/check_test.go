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
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils/testutils"
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
				Transport: testutils.NewRoundTripperFunc(nil, func(_ http.RoundTripper, req *http.Request) (*http.Response, error) {
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
