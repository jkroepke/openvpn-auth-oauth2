package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"

	"github.com/jkroepke/openvpn-auth-oauth2/pkg/internal/utils"
)

// Pagination URL patterns
// https://developer.GitHub.com/v3/#pagination
var (
	reNext = regexp.MustCompile("<([^>]+)>; rel=\"next\"")
	reLast = regexp.MustCompile("<([^>]+)>; rel=\"last\"")
)

func get[T any](ctx context.Context, accessToken string, apiURL string, data *T) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return "", fmt.Errorf("error creating request context with URL %s: %w", apiURL, err)
	}

	req.Header.Add("Authorization", utils.StringConcat("Bearer ", accessToken))
	req.Header.Add("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("error calling GitHub api %s: %w", apiURL, err)
	} else if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("error from GitHub api %s http status code: %d", apiURL, resp.StatusCode)
	}

	defer resp.Body.Close()

	if err = json.NewDecoder(resp.Body).Decode(data); err != nil {
		return "", fmt.Errorf("unable to decode json: %w", err)
	}

	return getPagination(apiURL, resp), nil
}

func getPagination(apiURL string, resp *http.Response) string {
	if resp == nil {
		return ""
	}

	links := resp.Header.Get("Link")
	if len(reLast.FindStringSubmatch(links)) > 1 {
		lastPageURL := reLast.FindStringSubmatch(links)[1]
		if apiURL == lastPageURL {
			return ""
		}
	} else {
		return ""
	}

	if len(reNext.FindStringSubmatch(links)) > 1 {
		return reNext.FindStringSubmatch(links)[1]
	}

	return ""
}
