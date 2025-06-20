package utils

import "net/http"

type UserAgentTransport struct {
	rt http.RoundTripper
}

// NewUserAgentTransport returns a transport that sets a default User-Agent
// header for all requests. If rt is nil the http.DefaultTransport is used.
func NewUserAgentTransport(rt http.RoundTripper) *UserAgentTransport {
	if rt == nil {
		rt = http.DefaultTransport
	}

	return &UserAgentTransport{rt}
}

// RoundTrip implements http.RoundTripper, adding the User-Agent header before
// delegating to the wrapped RoundTripper.
func (adt *UserAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Add("User-Agent", "openvpn-auth-oauth2")

	return adt.rt.RoundTrip(req) //nolint: wrapcheck
}
