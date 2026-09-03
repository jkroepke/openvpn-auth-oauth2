package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	githubAPIHost = "api.github.com"
	// Successful API responses are limited to 1 MiB.
	maxResponseBodySize = 1 << 20
	// Error responses are retained only as a 4 KiB diagnostic excerpt.
	maxErrorResponseBodySize = 4 << 10
)

// get performs an authenticated GitHub API request and decodes the JSON response.
func get[T any](ctx context.Context, httpClient *http.Client, accessToken, apiURL string, data *T) (string, error) {
	if err := validateAPIURL(apiURL); err != nil {
		return "", err
	}

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

	bodyLimit := maxResponseBodySize
	if resp.StatusCode != http.StatusOK {
		bodyLimit = maxErrorResponseBodySize
	}

	respBody, truncated, err := readResponseBody(resp.Body, bodyLimit)
	if err != nil {
		return "", fmt.Errorf("unable to read body from GitHub API %s: http status code: %d; error: %w", apiURL, resp.StatusCode, err)
	}

	if resp.StatusCode != http.StatusOK {
		truncationMarker := ""
		if truncated {
			truncationMarker = " [truncated]"
		}

		return "", fmt.Errorf(
			"error from GitHub API %s: http status code: %d; message: %s%s",
			apiURL,
			resp.StatusCode,
			respBody,
			truncationMarker,
		)
	}

	if truncated {
		return "", fmt.Errorf("response body from GitHub API %s exceeds the %d byte limit", apiURL, maxResponseBodySize)
	}

	if err = json.Unmarshal(respBody, data); err != nil {
		return "", fmt.Errorf("unable to decode JSON from GitHub API %s: '%s': %w", apiURL, respBody, err)
	}

	return getPagination(apiURL, resp)
}

func validateAPIURL(apiURL string) error {
	parsedURL, err := url.Parse(apiURL)
	if err != nil {
		return fmt.Errorf("unable to parse GitHub API URL %q: %w", apiURL, err)
	}

	if parsedURL.Scheme != "https" || parsedURL.Host != githubAPIHost {
		return fmt.Errorf("untrusted GitHub API URL %q", apiURL)
	}

	return nil
}

func readResponseBody(body io.Reader, limit int) ([]byte, bool, error) {
	responseBody, err := io.ReadAll(io.LimitReader(body, int64(limit+1)))
	if err != nil {
		return nil, false, fmt.Errorf("read limited response body: %w", err)
	}

	if len(responseBody) <= limit {
		return responseBody, false, nil
	}

	return responseBody[:limit], true, nil
}

// getPagination returns the next GitHub pagination URL when more pages are available.
func getPagination(apiURL string, resp *http.Response) (string, error) {
	if resp == nil {
		return "", nil
	}

	links := resp.Header.Get("Link")

	nextPageURL, lastPageURL := parsePaginationLinks(links)
	if lastPageURL == "" {
		return "", nil
	}

	for _, paginationURL := range []string{nextPageURL, lastPageURL} {
		if paginationURL == "" {
			continue
		}

		if err := validateAPIURL(paginationURL); err != nil {
			return "", fmt.Errorf("invalid GitHub pagination URL: %w", err)
		}
	}

	if apiURL == lastPageURL {
		return "", nil
	}

	return nextPageURL, nil
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
