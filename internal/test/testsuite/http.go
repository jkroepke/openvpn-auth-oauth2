package testsuite

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

// RoundTripperFunc wraps an http.RoundTripper and allows a custom function to
// intercept each request.
type RoundTripperFunc struct {
	fn func(rt http.RoundTripper, req *http.Request) (*http.Response, error)
	rt http.RoundTripper
}

// NewRoundTripperFunc returns a RoundTripperFunc that calls fn with the wrapped
// RoundTripper for each request.
func NewRoundTripperFunc(rt http.RoundTripper, fn func(rt http.RoundTripper, req *http.Request) (*http.Response, error)) *RoundTripperFunc {
	return &RoundTripperFunc{fn, rt}
}

// RoundTrip implements http.RoundTripper.
func (f *RoundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f.fn(f.rt, req)
}

// MockRoundTripper mocks selected HTTP calls while delegating everything else to
// the provided RoundTripper.
type MockRoundTripper struct {
	rt http.RoundTripper
}

// NewMockRoundTripper creates a MockRoundTripper. If rt is nil the default
// transport is used.
func NewMockRoundTripper(rt http.RoundTripper) *MockRoundTripper {
	if rt == nil {
		rt = http.DefaultTransport
	}

	return &MockRoundTripper{rt}
}

// RoundTrip implements http.RoundTripper and returns mocked responses for
// specific hosts.
//
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

// WaitUntilListening tries to connect to a network address until it is
// available. It returns the connection or an error after several retries.
func WaitUntilListening(tb testing.TB, network, address string) (net.Conn, error) {
	tb.Helper()

	var (
		conn net.Conn
		err  error
	)

	dialer := &net.Dialer{Timeout: 100 * time.Millisecond}

	for range 10 {
		conn, err = dialer.DialContext(tb.Context(), network, address)
		if err == nil {
			return conn, nil
		}

		if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.Errno(10061)) {
			time.Sleep(50 * time.Millisecond)

			continue
		}
	}

	return nil, fmt.Errorf("listener not listening: %w", err)
}
