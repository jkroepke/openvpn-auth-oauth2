package utils

import "net/http"

type UserAgentTransport struct {
	T http.RoundTripper
}

func NewUserAgentTransport(T http.RoundTripper) *UserAgentTransport {
	if T == nil {
		T = http.DefaultTransport
	}
	return &UserAgentTransport{T}
}

func (adt *UserAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Add("User-Agent", "openvpn-auth-oauth2")
	return adt.T.RoundTrip(req)
}
