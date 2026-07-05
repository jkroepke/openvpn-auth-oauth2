package github //nolint:testpackage

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetPagination(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		apiURL   string
		link     string
		expected string
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

			nextURL := getPagination(testCase.apiURL, response)

			require.Equal(t, testCase.expected, nextURL)
		})
	}
}
