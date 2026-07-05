package utils

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewOAuth2HTTPClientUsesTunedDefaultTransport(t *testing.T) {
	t.Parallel()

	client := NewOAuth2HTTPClient(nil)

	userAgentTransport, ok := client.Transport.(*UserAgentTransport)
	require.True(t, ok)

	transport, ok := userAgentTransport.rt.(*http.Transport)
	require.True(t, ok)

	assert.NotNil(t, transport.Proxy)
	assert.NotNil(t, transport.DialContext)
	assert.True(t, transport.ForceAttemptHTTP2)
	assert.Equal(t, oAuth2HTTPMaxIdleConns, transport.MaxIdleConns)
	assert.Equal(t, oAuth2HTTPMaxIdleConnsPerHost, transport.MaxIdleConnsPerHost)
	assert.Equal(t, oAuth2HTTPIdleConnTimeout, transport.IdleConnTimeout)
	assert.Equal(t, oAuth2HTTPHandshakeTimeout, transport.TLSHandshakeTimeout)
	assert.Equal(t, oAuth2HTTPContinueTimeout, transport.ExpectContinueTimeout)
}

func TestNewOAuth2HTTPClientUsesProvidedTransport(t *testing.T) {
	t.Parallel()

	roundTripper := &testRoundTripper{}
	client := NewOAuth2HTTPClient(roundTripper)

	userAgentTransport, ok := client.Transport.(*UserAgentTransport)
	require.True(t, ok)
	assert.Same(t, roundTripper, userAgentTransport.rt)
}

type testRoundTripper struct{}

func (t *testRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{}, nil
}
