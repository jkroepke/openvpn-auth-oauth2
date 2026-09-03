package google //nolint:testpackage

import (
	"net/http"
	"net/http/httptest"
	"net/url"
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
			wantErrContains: "response body from Google API https://cloudidentity.googleapis.com/test exceeds the 1048576 byte limit",
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

			apiURL := &url.URL{Scheme: "https", Host: "cloudidentity.googleapis.com", Path: "/test"}

			var data any

			err := get[any](t.Context(), httpClient, "token", apiURL, &data)

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
