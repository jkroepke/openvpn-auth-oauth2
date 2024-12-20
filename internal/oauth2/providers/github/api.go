package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
)

// Pagination URL patterns
// https://developer.GitHub.com/v3/#pagination
var (
	reNext = regexp.MustCompile("<([^>]+)>; rel=\"next\"")
	reLast = regexp.MustCompile("<([^>]+)>; rel=\"last\"")
)

func get[T any](ctx context.Context, httpClient *http.Client, accessToken, apiURL string, data *T) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return "", fmt.Errorf("error creating request context with URL %s: %w", apiURL, err)
	}

	req.Header.Add("Authorization", utils.StringConcat("Bearer ", accessToken))
	req.Header.Add("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("error calling GitHub API %s: %w", apiURL, err)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("unable to read body from GitHub API %s: http status code: %d; error: %w", apiURL, resp.StatusCode, err)
	}

	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("error from GitHub API %s: http status code: %d; message: %s", apiURL, resp.StatusCode, respBody)
	}

	if err = json.Unmarshal(respBody, data); err != nil {
		return "", fmt.Errorf("unable to decode JSON from GitHub API %s: '%s': %w", apiURL, respBody, err)
	}

	return getPagination(apiURL, resp), nil
}

func getPagination(apiURL string, resp *http.Response) string {
	if resp == nil {
		return ""
	}

	links := resp.Header.Get("Link")
	if len(reLast.FindStringSubmatch(links)) == 0 {
		return ""
	}

	lastPageURL := reLast.FindStringSubmatch(links)[1]
	if apiURL == lastPageURL {
		return ""
	}

	if len(reNext.FindStringSubmatch(links)) > 1 {
		return reNext.FindStringSubmatch(links)[1]
	}

	return ""
}
