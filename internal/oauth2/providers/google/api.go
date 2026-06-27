package google

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
)

//nolint:tagliatelle // The API response is a JSON object with a dynamic structure.
type groupMembershipPage struct {
	NextPageToken string `json:"nextPageToken"`
	Memberships   []struct {
		Name string `json:"name"`
	} `json:"memberships"`
}

//nolint:tagliatelle // hasMembership matches the Google Cloud Identity API response field name.
type checkTransitiveMembershipResponse struct {
	HasMembership bool `json:"hasMembership"`
}

type apiError struct {
	Error struct {
		Message string `json:"message"`
	} `json:"error"`
}

// checkGroupMembership fetches the groups from a user using the Google Identity API.
func (p Provider) checkGroupMembership(ctx context.Context, groupID string, userInfo types.UserInfo, tokens *idtoken.IDToken) (bool, error) {
	// https://cloud.google.com/identity/docs/reference/rest/v1beta1/groups.memberships/searchDirectGroups
	apiURL := &url.URL{
		Scheme: "https",
		Host:   "cloudidentity.googleapis.com",
		Path:   fmt.Sprintf("/v1/groups/%s/memberships", groupID),
	}

	var (
		result groupMembershipPage
		err    error
	)

	for {
		if err = get[groupMembershipPage](ctx, p.httpClient, tokens.AccessToken, apiURL, &result); err != nil {
			return false, err
		}

		for _, membership := range result.Memberships {
			if fmt.Sprintf("groups/%s/memberships/%s", groupID, userInfo.Subject) == membership.Name {
				return true, nil
			}
		}

		if result.NextPageToken == "" {
			break
		}

		apiURL.RawQuery = "pageToken=" + result.NextPageToken
	}

	return false, nil
}

// checkTransitiveGroupMembership uses the Cloud Identity API to determine whether the user is a
// transitive (direct or nested) member of the given group.
// https://cloud.google.com/identity/docs/reference/rest/v1/groups.memberships/checkTransitiveMembership
func (p Provider) checkTransitiveGroupMembership(ctx context.Context, groupID string, userInfo types.UserInfo, tokens *idtoken.IDToken) (bool, error) {
	memberKey := userInfo.Email
	if memberKey == "" {
		memberKey = userInfo.Subject
	}

	query := url.Values{}
	query.Set("query", fmt.Sprintf("member_key_id == '%s'", memberKey))

	apiURL := &url.URL{
		Scheme:   "https",
		Host:     "cloudidentity.googleapis.com",
		Path:     fmt.Sprintf("/v1/groups/%s/memberships:checkTransitiveMembership", groupID),
		RawQuery: query.Encode(),
	}

	var result checkTransitiveMembershipResponse

	if err := get[checkTransitiveMembershipResponse](ctx, p.httpClient, tokens.AccessToken, apiURL, &result); err != nil {
		return false, err
	}

	return result.HasMembership, nil
}

// get calls the Google API and decodes the response into the data struct.
func get[T any](ctx context.Context, httpClient *http.Client, accessToken string, apiURL *url.URL, data *T) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL.String(), nil)
	if err != nil {
		return fmt.Errorf("error creating request context with URL %s: %w", apiURL, err)
	}

	req.Header.Add("Authorization", "Bearer "+accessToken)
	req.Header.Add("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("error calling Google API %s: %w", apiURL, err)
	}

	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("unable to read body from Google API %s: http status code: %d; error: %w", apiURL, resp.StatusCode, err)
	}

	if resp.StatusCode != http.StatusOK {
		var apiErr apiError

		if bytes.HasPrefix(respBody, []byte("{")) {
			_ = json.Unmarshal(respBody, &apiErr)
		}

		if strings.HasPrefix(apiErr.Error.Message, "Error(4001):") {
			// This error indicates that the current user does not have the required permissions to access the group.
			// Clear the data by setting it to zero value
			var zero T

			*data = zero

			return nil
		}

		return fmt.Errorf("error from Google API %s: http status code: %d; message: %s", apiURL, resp.StatusCode, apiErr.Error.Message)
	}

	if err = json.Unmarshal(respBody, data); err != nil {
		return fmt.Errorf("unable to decode JSON from Google API %s: '%s': %w", apiURL, respBody, err)
	}

	return nil
}
