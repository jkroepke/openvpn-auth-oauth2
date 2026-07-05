package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// get performs an authenticated GitHub API request and decodes the JSON response.
func get[T any](ctx context.Context, httpClient *http.Client, accessToken, apiURL string, data *T) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return "", fmt.Errorf("error creating request context with URL %s: %w", apiURL, err)
	}

	req.Header.Add("Authorization", "Bearer "+accessToken)
	req.Header.Add("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("error calling GitHub API %s: %w", apiURL, err)
	}

	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("unable to read body from GitHub API %s: http status code: %d; error: %w", apiURL, resp.StatusCode, err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("error from GitHub API %s: http status code: %d; message: %s", apiURL, resp.StatusCode, respBody)
	}

	if err = json.Unmarshal(respBody, data); err != nil {
		return "", fmt.Errorf("unable to decode JSON from GitHub API %s: '%s': %w", apiURL, respBody, err)
	}

	return getPagination(apiURL, resp), nil
}

// getPagination returns the next GitHub pagination URL when more pages are available.
func getPagination(apiURL string, resp *http.Response) string {
	if resp == nil {
		return ""
	}

	links := resp.Header.Get("Link")

	nextPageURL, lastPageURL := parsePaginationLinks(links)
	if lastPageURL == "" {
		return ""
	}

	if apiURL == lastPageURL {
		return ""
	}

	return nextPageURL
}

func parsePaginationLinks(links string) (string, string) {
	var nextPageURL, lastPageURL string

	for links != "" {
		links = strings.TrimSpace(links)

		if !strings.HasPrefix(links, "<") {
			return nextPageURL, lastPageURL
		}

		targetEnd := strings.IndexByte(links, '>')
		if targetEnd < 0 {
			return nextPageURL, lastPageURL
		}

		linkURL := links[1:targetEnd]
		attrs, remaining := splitPaginationLinkAttrs(links[targetEnd+1:])

		for attr := range strings.SplitSeq(attrs, ";") {
			switch strings.TrimSpace(attr) {
			case `rel="next"`:
				nextPageURL = linkURL
			case `rel="last"`:
				lastPageURL = linkURL
			}
		}

		links = remaining
	}

	return nextPageURL, lastPageURL
}

func splitPaginationLinkAttrs(attrs string) (string, string) {
	for i := range attrs {
		if attrs[i] != ',' {
			continue
		}

		remaining := strings.TrimSpace(attrs[i+1:])
		if strings.HasPrefix(remaining, "<") {
			return attrs[:i], remaining
		}
	}

	return attrs, ""
}
