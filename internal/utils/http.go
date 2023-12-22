package utils

import "net/http"

type UserAgentTransport struct {
	rt http.RoundTripper
}

func NewUserAgentTransport(rt http.RoundTripper) *UserAgentTransport {
	if rt == nil {
		rt = http.DefaultTransport
	}

	return &UserAgentTransport{rt}
}

func (adt *UserAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Add("User-Agent", "openvpn-auth-oauth2")

	return adt.rt.RoundTrip(req) //nolint: wrapcheck
}
