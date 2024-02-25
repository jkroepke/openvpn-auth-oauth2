package google_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/generic"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/google"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/pkg/testutils"
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
			[]string{},
			"",
		},
		{
			"groups empty",
			`{"memberships": [], "nextPageToken": ""}`,
			[]string{},
			"",
		},
		{
			"groups present",
			`{"memberships": [{"groupKey": {"id": "apple@google.com"}}], "nextPageToken": ""}`,
			[]string{},
			"",
		},
		{
			"groups present with nextPageToken",
			`{"memberships": [{"groupKey": {"id": "apple@google.com"}}], "nextPageToken": "token"}`,
			[]string{},
			"",
		},
		{
			"configure one group",
			`{"memberships": [{"groupKey": {"id": "apple@google.com"}}], "nextPageToken": ""}`,
			[]string{"apple@google.com"},
			"",
		},
		{
			"access token is empty",
			`ERROR`,
			[]string{"apple"},
			"access token is empty",
		},
		{
			"invalid json",
			`ERROR`,
			[]string{"apple"},
			"unable to decode JSON from Google API https://cloudidentity.googleapis.com/v1/groups/-/memberships:searchDirectGroups?query=member_key_id=='ID': 'ERROR': invalid character 'E' looking for beginning of value",
		},
		{
			"configure one group, groups not present",
			`{"error": {"message": "error"}}`,
			[]string{"apple"},
			"error from Google API https://cloudidentity.googleapis.com/v1/groups/-/memberships:searchDirectGroups?query=member_key_id=='ID': http status code: 500; message: error",
		},
		{
			"configure two group, none match",
			`{"memberships": [{"groupKey": {"id": "pineapple@google.com"}}], "nextPageToken": ""}`,
			[]string{"apple@google.com", "pear@google.com"},
			generic.ErrMissingRequiredGroup.Error(),
		},
		{
			"configure two group, missing one",
			`{"memberships": [{"groupKey": {"id": "apple@google.com"}}], "nextPageToken": ""}`,
			[]string{"apple@google.com", "pear@google.com"},
			"",
		},
		{
			"configure two group",
			`{"memberships": [{"groupKey": {"id": "apple@google.com"}},{"groupKey": {"id": "pear@google.com"}}], "nextPageToken": ""}`,
			[]string{"apple@google.com", "pear@google.com"},
			"",
		},
	} {
		tt := tt

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
				Transport: testutils.NewRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
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

			err = provider.CheckUser(context.Background(), state.State{}, types.UserData{Email: "ID"}, token)

			if tt.err == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.EqualError(t, err, tt.err)
			}
		})
	}
}
