package testsuite

import (
	"net/http"
)

type Options func(*Suite) *Suite

func WithHTTPTransport(rt http.RoundTripper) Options {
	return func(s *Suite) *Suite {
		s.rt = rt

		return s
	}
}
