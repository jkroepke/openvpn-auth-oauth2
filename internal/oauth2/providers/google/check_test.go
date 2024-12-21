package google_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	oauth3 "github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/google"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/oauth2"
)

func TestValidateGroups(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
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
			"configure two group, none match",
			`{"memberships": [{"name": "groups/000000000000002/memberships/123456789101112131416", "memberKey": {"id": "user@example.com"}, "roles": [{"name": "MEMBER"}], "preferredMemberKey": {"id": "user@example.com"}}], "nextPageToken": ""}`,
			[]string{"000000000000000", "000000000000001"},
			oauth3.ErrMissingRequiredGroup.Error(),
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
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			token := &oidc.Tokens[*idtoken.Claims]{
				Token: &oauth2.Token{
					AccessToken: "TOKEN",
				},
				IDTokenClaims: &idtoken.Claims{},
			}

			if tt.name == "access token is empty" {
				token.AccessToken = ""
			}

			conf := config.Config{
				OAuth2: config.OAuth2{
					Validate: config.OAuth2Validate{
						Groups: tt.requiredGroups,
					},
				},
			}

			httpClient := &http.Client{
				Transport: testutils.NewRoundTripperFunc(nil, func(_ http.RoundTripper, req *http.Request) (*http.Response, error) {
					resp := httptest.NewRecorder()
					if strings.Contains(tt.tokenGroups, "error") {
						resp.WriteHeader(http.StatusInternalServerError)
					}

					if req.URL.Query().Has("pageToken") {
						_, _ = resp.WriteString(`{"memberships": [], "nextPageToken": ""}`)
					} else {
						_, _ = resp.WriteString(tt.tokenGroups)
					}

					return resp.Result(), nil
				}),
			}

			provider, err := google.NewProvider(context.Background(), conf, httpClient)
			require.NoError(t, err)

			err = provider.CheckUser(context.Background(), state.State{}, types.UserData{Subject: "123456789101112131415"}, token)

			if tt.err == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.EqualError(t, err, tt.err)
			}
		})
	}
}
