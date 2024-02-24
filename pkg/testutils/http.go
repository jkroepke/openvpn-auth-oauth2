package testutils

import "net/http"

type RoundTripperFunc struct {
	Fn func(rt http.RoundTripper, req *http.Request) (*http.Response, error)
	Rt http.RoundTripper
}

func (f *RoundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f.Fn(f.Rt, req)
}
