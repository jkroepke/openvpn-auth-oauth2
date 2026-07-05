package utils

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
)

const (
	oAuth2HTTPClientTimeout       = 30 * time.Second
	oAuth2HTTPDialTimeout         = 30 * time.Second
	oAuth2HTTPKeepAlive           = 30 * time.Second
	oAuth2HTTPIdleConnTimeout     = 90 * time.Second
	oAuth2HTTPHandshakeTimeout    = 10 * time.Second
	oAuth2HTTPContinueTimeout     = 1 * time.Second
	oAuth2HTTPMaxIdleConns        = 128
	oAuth2HTTPMaxIdleConnsPerHost = 32
)

var (
	ErrOAuth2ProviderRedirectHost      = errors.New("oauth2 provider redirect changes host")
	ErrOAuth2ProviderRedirectDowngrade = errors.New("oauth2 provider redirect downgrades HTTPS")
)

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

// NewOAuth2HTTPClient returns the outbound HTTP client used for provider calls.
func NewOAuth2HTTPClient(rt http.RoundTripper) *http.Client {
	if rt == nil {
		rt = newOAuth2HTTPTransport()
	}

	return &http.Client{
		Transport:     NewUserAgentTransport(rt),
		CheckRedirect: CheckOAuth2ProviderRedirect,
		Timeout:       oAuth2HTTPClientTimeout,
	}
}

func newOAuth2HTTPTransport() *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   oAuth2HTTPDialTimeout,
			KeepAlive: oAuth2HTTPKeepAlive,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          oAuth2HTTPMaxIdleConns,
		MaxIdleConnsPerHost:   oAuth2HTTPMaxIdleConnsPerHost,
		IdleConnTimeout:       oAuth2HTTPIdleConnTimeout,
		TLSHandshakeTimeout:   oAuth2HTTPHandshakeTimeout,
		ExpectContinueTimeout: oAuth2HTTPContinueTimeout,
	}
}

// CheckOAuth2ProviderRedirect restricts provider redirects to the original host.
func CheckOAuth2ProviderRedirect(req *http.Request, via []*http.Request) error {
	if len(via) == 0 {
		return nil
	}

	originalURL := via[0].URL

	if req.URL.Host != originalURL.Host {
		return fmt.Errorf("%w: %s to %s", ErrOAuth2ProviderRedirectHost, originalURL.Host, req.URL.Host)
	}

	if originalURL.Scheme == "https" && req.URL.Scheme != "https" {
		return fmt.Errorf("%w: %s to %s", ErrOAuth2ProviderRedirectDowngrade, originalURL.Scheme, req.URL.Scheme)
	}

	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}

	return nil
}

// RoundTrip implements http.RoundTripper, adding the User-Agent header before
// delegating to the wrapped RoundTripper.
func (adt *UserAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Add("User-Agent", "openvpn-auth-oauth2")

	return adt.rt.RoundTrip(req) //nolint: wrapcheck
}
