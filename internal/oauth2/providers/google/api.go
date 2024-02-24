package google

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type groupPage struct {
	NextPageToken string `json:"nextPageToken"`
	Memberships   []struct {
		GroupKey struct {
			ID string `json:"id"`
		} `json:"groupKey"`
	} `json:"memberships"`
}

type apiError struct {
	Error struct {
		Message string `json:"message"`
	} `json:"error"`
}

// fetchGroupsFromIdentityAPI fetches the groups from a user using the Google Identity API.
func (p *Provider) fetchGroupsFromIdentityAPI(ctx context.Context, userData types.UserData, tokens *oidc.Tokens[*idtoken.Claims]) ([]string, error) {
	// https://developers.google.com/admin-sdk/directory/reference/rest/v1/groups/list
	apiQuery := fmt.Sprintf("query=member_key_id=='%s'", userData.Email)
	apiURL := &url.URL{
		Scheme:   "https",
		Host:     "cloudidentity.googleapis.com",
		Path:     "/v1/groups/-/memberships:searchDirectGroups",
		RawQuery: apiQuery,
	}

	var groups []string

	for {
		var (
			result groupPage
			err    error
		)

		if err = get[groupPage](ctx, p.httpClient, tokens.AccessToken, apiURL, &result); err != nil {
			return nil, err
		}

		for _, group := range result.Memberships {
			groups = append(groups, group.GroupKey.ID)
		}

		if result.NextPageToken == "" {
			break
		}

		apiURL.RawQuery = fmt.Sprintf("%s&pageToken=%s", apiQuery, result.NextPageToken)
	}

	return groups, nil
}

// get calls the Google API and decodes the response into the data struct.
func get[T any](ctx context.Context, httpClient *http.Client, accessToken string, apiURL *url.URL, data *T) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL.String(), nil)
	if err != nil {
		return fmt.Errorf("error creating request context with URL %s: %w", apiURL, err)
	}

	req.Header.Add("Authorization", utils.StringConcat("Bearer ", accessToken))
	req.Header.Add("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("error calling Google API %s: %w", apiURL, err)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("unable to read body from Google API %s: http status code: %d; error: %w", apiURL, resp.StatusCode, err)
	}

	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var apiErr apiError

		if err == nil && bytes.HasPrefix(respBody, []byte("{")) {
			_ = json.Unmarshal(respBody, &apiErr)
		}

		return fmt.Errorf("error from Google API %s: http status code: %d; message: %s", apiURL, resp.StatusCode, apiErr.Error.Message)
	}

	defer resp.Body.Close()

	if err = json.Unmarshal(respBody, data); err != nil {
		return fmt.Errorf("unable to decode JSON from Google API %s: '%s': %w", apiURL, respBody, err)
	}

	return nil
}
