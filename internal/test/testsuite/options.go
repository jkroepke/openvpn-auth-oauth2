package testsuite

import (
	"net/http"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/test/testlogger"
)

type Options func(*Suite) *Suite

func WithHTTPTransport(rt http.RoundTripper) Options {
	return func(s *Suite) *Suite {
		s.rt = rt

		return s
	}
}

// WithDiscardLogger configures the suite to format logs without retaining them.
func WithDiscardLogger() Options {
	return func(s *Suite) *Suite {
		s.logger = testlogger.NewDiscard()

		return s
	}
}
