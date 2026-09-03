package github //nolint:testpackage

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type apiRoundTripper func(*http.Request) (*http.Response, error)

func (fn apiRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func TestGetResponseBodyLimits(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		statusCode      int
		body            string
		wantErrContains string
		wantErrExcludes string
	}{
		{
			name:       "successful response at limit",
			statusCode: http.StatusOK,
			body:       "[]" + strings.Repeat(" ", maxResponseBodySize-2),
		},
		{
			name:            "successful response exceeds limit",
			statusCode:      http.StatusOK,
			body:            strings.Repeat(" ", maxResponseBodySize+1),
			wantErrContains: "response body from GitHub API https://api.github.com/test exceeds the 1048576 byte limit",
		},
		{
			name:            "error response is truncated",
			statusCode:      http.StatusInternalServerError,
			body:            "visible" + strings.Repeat("x", maxErrorResponseBodySize) + "hidden",
			wantErrContains: "visible",
			wantErrExcludes: "hidden",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			httpClient := &http.Client{
				Transport: apiRoundTripper(func(_ *http.Request) (*http.Response, error) {
					response := httptest.NewRecorder()
					response.WriteHeader(testCase.statusCode)
					_, _ = response.WriteString(testCase.body)

					return response.Result(), nil
				}),
			}

			var data any

			_, err := get[any](t.Context(), httpClient, "token", "https://api.github.com/test", &data)

			if testCase.wantErrContains == "" {
				require.NoError(t, err)

				return
			}

			require.ErrorContains(t, err, testCase.wantErrContains)

			if testCase.wantErrExcludes != "" {
				require.NotContains(t, err.Error(), testCase.wantErrExcludes)
				require.ErrorContains(t, err, "[truncated]")
			}
		})
	}
}

func TestGetRejectsUntrustedAPIURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		apiURL string
	}{
		{
			name:   "insecure scheme",
			apiURL: "http://api.github.com/user/orgs",
		},
		{
			name:   "different host",
			apiURL: "https://example.com/user/orgs",
		},
		{
			name:   "host suffix",
			apiURL: "https://api.github.com.example.com/user/orgs",
		},
		{
			name:   "explicit port",
			apiURL: "https://api.github.com:443/user/orgs",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			requestSent := false
			httpClient := &http.Client{
				Transport: apiRoundTripper(func(_ *http.Request) (*http.Response, error) {
					requestSent = true

					return nil, errors.New("unexpected request")
				}),
			}

			var data any

			_, err := get[any](t.Context(), httpClient, "token", testCase.apiURL, &data)

			require.ErrorContains(t, err, "untrusted GitHub API URL")
			require.False(t, requestSent)
		})
	}
}

func TestGetPagination(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		apiURL   string
		link     string
		expected string
		wantErr  string
	}{
		{
			name:   "nil response",
			apiURL: "https://api.github.com/user/orgs?page=1",
		},
		{
			name:   "missing link header",
			apiURL: "https://api.github.com/user/orgs?page=1",
		},
		{
			name:   "malformed link header",
			apiURL: "https://api.github.com/user/orgs?page=1",
			link:   `not a github link header`,
		},
		{
			name:   "last page",
			apiURL: "https://api.github.com/user/orgs?page=2",
			link:   `<https://api.github.com/user/orgs?page=2>; rel="last"`,
		},
		{
			name:     "next page before last",
			apiURL:   "https://api.github.com/user/orgs?page=1",
			link:     `<https://api.github.com/user/orgs?page=2>; rel="next", <https://api.github.com/user/orgs?page=3>; rel="last"`,
			expected: "https://api.github.com/user/orgs?page=2",
		},
		{
			name:   "last link without next link",
			apiURL: "https://api.github.com/user/orgs?page=1",
			link:   `<https://api.github.com/user/orgs?page=3>; rel="last"`,
		},
		{
			name:     "next link after last link",
			apiURL:   "https://api.github.com/user/orgs?page=1",
			link:     `<https://api.github.com/user/orgs?page=3>; rel="last", <https://api.github.com/user/orgs?page=2>; rel="next"`,
			expected: "https://api.github.com/user/orgs?page=2",
		},
		{
			name:     "next url contains separators",
			apiURL:   "https://api.github.com/user/orgs?affiliation=owner,collaborator;admin&page=1",
			link:     `<https://api.github.com/user/orgs?affiliation=owner,collaborator;admin&page=2>; rel="next", <https://api.github.com/user/orgs?affiliation=owner,collaborator;admin&page=3>; rel="last"`,
			expected: "https://api.github.com/user/orgs?affiliation=owner,collaborator;admin&page=2",
		},
		{
			name:    "untrusted next url",
			apiURL:  "https://api.github.com/user/orgs?page=1",
			link:    `<https://example.com/user/orgs?page=2>; rel="next", <https://api.github.com/user/orgs?page=3>; rel="last"`,
			wantErr: "invalid GitHub pagination URL: untrusted GitHub API URL \"https://example.com/user/orgs?page=2\"",
		},
		{
			name:    "untrusted last url",
			apiURL:  "https://api.github.com/user/orgs?page=1",
			link:    `<https://api.github.com/user/orgs?page=2>; rel="next", <http://api.github.com/user/orgs?page=3>; rel="last"`,
			wantErr: "invalid GitHub pagination URL: untrusted GitHub API URL \"http://api.github.com/user/orgs?page=3\"",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			var response *http.Response
			if testCase.name != "nil response" {
				response = &http.Response{Header: http.Header{}}
				if testCase.link != "" {
					response.Header.Set("Link", testCase.link)
				}
			}

			nextURL, err := getPagination(testCase.apiURL, response)
			if testCase.wantErr != "" {
				require.EqualError(t, err, testCase.wantErr)
				require.Empty(t, nextURL)

				return
			}

			require.NoError(t, err)
			require.Equal(t, testCase.expected, nextURL)
		})
	}
}
