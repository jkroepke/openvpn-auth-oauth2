package testutils

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"syscall"
	"testing"
	"time"
)

type RoundTripperFunc struct {
	fn func(req *http.Request) (*http.Response, error)
}

func NewRoundTripperFunc(fn func(req *http.Request) (*http.Response, error)) *RoundTripperFunc {
	return &RoundTripperFunc{fn}
}

func (f *RoundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f.fn(req)
}

type MockRoundTripper struct {
	rt http.RoundTripper
}

func NewMockRoundTripper(rt http.RoundTripper) *MockRoundTripper {
	if rt == nil {
		rt = http.DefaultTransport
	}

	return &MockRoundTripper{rt}
}

//nolint:cyclop
func (f *MockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	switch req.URL.Host {
	case "cloudidentity.googleapis.com":
		resp := httptest.NewRecorder()
		_, _ = resp.WriteString(`{"memberships": [], "nextPageToken": ""}`)

		return resp.Result(), nil
	case "api.github.com":
		switch req.URL.Path {
		case "/user":
			resp := httptest.NewRecorder()
			_, _ = resp.WriteString(`{"login": "test-user", "id": 123456, "email": "test-user@localhost"}`)
			resp.Header().Set("Content-Type", "application/json")

			return resp.Result(), nil
		case "/user/orgs", "/user/teams":
			resp := httptest.NewRecorder()
			_, _ = resp.WriteString(`[]`)
			resp.Header().Set("Content-Type", "application/json")

			return resp.Result(), nil
		default:
			return f.rt.RoundTrip(req) //nolint:wrapcheck
		}

	case "github.com":
		// https://blog.seriesci.com/how-to-mock-oauth-in-go/
		switch req.URL.Path {
		case "/login/oauth/authorize":
			state := req.FormValue("state")
			redirectURI := req.FormValue("redirect_uri")

			uri, err := url.Parse(redirectURI)
			if err != nil {
				return nil, err //nolint:wrapcheck
			}

			v := url.Values{}
			v.Set("code", "code")
			v.Set("state", state)
			uri.RawQuery = v.Encode()

			resp := httptest.NewRecorder()
			resp.Header().Set("Location", uri.String())
			resp.WriteHeader(http.StatusTemporaryRedirect)

			return resp.Result(), nil
		case "/login/oauth/access_token":
			resp := httptest.NewRecorder()
			resp.Header().Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
			_, _ = resp.WriteString(`access_token=gho_mock&scope=read%3Aorg%2Cuser%3Aemail&token_type=bearer`)

			return resp.Result(), nil
		}

		return f.rt.RoundTrip(req) //nolint:wrapcheck
	default:
		return f.rt.RoundTrip(req) //nolint:wrapcheck
	}
}

func WaitUntilListening(tb testing.TB, listener net.Listener) error {
	tb.Helper()

	var err error

	for range 10 {
		_, err = net.DialTimeout(listener.Addr().Network(), listener.Addr().String(), 100*time.Millisecond)
		if err == nil {
			return nil
		}

		if errors.Is(err, syscall.ECONNREFUSED) {
			time.Sleep(100 * time.Millisecond)

			continue
		}
	}

	return fmt.Errorf("listener not listening: %w", err)
}
