package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
)

// Pagination URL patterns
// https://developer.github.com/v3/#pagination
var (
	reNext = regexp.MustCompile("<([^>]+)>; rel=\"next\"")
	reLast = regexp.MustCompile("<([^>]+)>; rel=\"last\"")
)

func get[T any](ctx context.Context, accessToken string, apiUrl string, t *T) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiUrl, nil)
	if err != nil {
		return "", err
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	req.Header.Add("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	} else if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("error from github api %s, http status code: %d", apiUrl, resp.StatusCode)
	}

	defer resp.Body.Close()

	if err := json.NewDecoder(resp.Body).Decode(t); err != nil {
		return "", err
	}

	return getPagination(apiUrl, resp), nil
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
