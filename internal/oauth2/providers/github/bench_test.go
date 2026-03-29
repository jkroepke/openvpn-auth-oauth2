package github //nolint:testpackage

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type benchmarkRoundTripper func(*http.Request) (*http.Response, error)

func (fn benchmarkRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func BenchmarkGetPagination(b *testing.B) {
	for _, tc := range []struct {
		name   string
		apiURL string
		link   string
	}{
		{
			name:   "no-pagination",
			apiURL: "https://api.github.com/user/orgs",
			link:   "",
		},
		{
			name:   "next-page",
			apiURL: "https://api.github.com/user/orgs?page=1",
			link:   `<https://api.github.com/user/orgs?page=2>; rel="next", <https://api.github.com/user/orgs?page=4>; rel="last"`,
		},
		{
			name:   "already-last-page",
			apiURL: "https://api.github.com/user/orgs?page=4",
			link:   `<https://api.github.com/user/orgs?page=4>; rel="last"`,
		},
	} {
		b.Run(tc.name, func(b *testing.B) {
			resp := &http.Response{Header: http.Header{"Link": []string{tc.link}}}

			var nextURL string

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				nextURL = getPagination(tc.apiURL, resp)
			}

			_ = nextURL
		})
	}
}

func BenchmarkGet(b *testing.B) {
	ctx := context.Background()
	client := &http.Client{
		Transport: benchmarkRoundTripper(func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"login":"octocat","id":1}`)),
			}, nil
		}),
	}

	apiURL := "https://api.github.com/user"

	var (
		nextURL string
		user    struct {
			Login string `json:"login"`
			ID    int    `json:"id"`
		}
	)

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		user = struct {
			Login string `json:"login"`
			ID    int    `json:"id"`
		}{}

		var err error

		nextURL, err = get(ctx, client, "TOKEN", apiURL, &user)
		if err != nil {
			b.Fatal(err)
		}
	}

	_ = nextURL
	_ = user
}
