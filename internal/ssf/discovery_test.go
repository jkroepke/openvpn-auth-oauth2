package ssf_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/ssf"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/ssf/ssftest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()

	parsed, err := url.Parse(raw)
	require.NoError(t, err)

	return parsed
}

func TestMetadataURLs(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		issuer string
		want   []string
	}{
		{"https://idp.example.com", []string{"https://idp.example.com/.well-known/ssf-configuration"}},
		{"https://idp.example.com/", []string{"https://idp.example.com/.well-known/ssf-configuration"}},
		{"https://idp.example.com/realms/vpn", []string{
			"https://idp.example.com/.well-known/ssf-configuration/realms/vpn",
			"https://idp.example.com/realms/vpn/.well-known/ssf-configuration",
		}},
		{"https://idp.example.com/realms/vpn/", []string{
			"https://idp.example.com/.well-known/ssf-configuration/realms/vpn",
			"https://idp.example.com/realms/vpn/.well-known/ssf-configuration",
		}},
	} {
		assert.Equal(t, tc.want, ssf.MetadataURLs(mustParseURL(t, tc.issuer)), tc.issuer)
	}
}

func TestDiscover(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		opts []ssftest.Option
	}{
		{name: "issuer without path"},
		{name: "inserted metadata location", opts: []ssftest.Option{ssftest.WithIssuerPath("/realms/vpn")}},
		{name: "appended metadata location", opts: []ssftest.Option{
			ssftest.WithIssuerPath("/realms/vpn"), ssftest.WithMetadataLocation(ssftest.MetadataAppended),
		}},
		{name: "several audiences", opts: []ssftest.Option{ssftest.WithAudience("https://a.example.com", "https://b.example.com")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			transmitter := ssftest.New(t, tc.opts...)

			discovery, err := ssf.Discover(t.Context(), transmitter.Client(), mustParseURL(t, transmitter.Issuer()), transmitter.Token())
			require.NoError(t, err)

			assert.Equal(t, transmitter.Issuer(), discovery.Metadata.Issuer)
			assert.Equal(t, transmitter.JWKSURI(), discovery.Metadata.JWKSURI)
			assert.Equal(t, transmitter.ConfigurationEndpoint(), discovery.Metadata.ConfigurationEndpoint)
			assert.Equal(t, transmitter.StreamIDs()[0], discovery.Stream.StreamID)
			assert.Equal(t, transmitter.PollEndpoint(), discovery.Stream.Delivery.EndpointURL)
			assert.ElementsMatch(t, transmitter.Audience(), discovery.Stream.Audience)
			assert.Contains(t, discovery.Stream.EventsDelivered, ssf.EventTypeSessionRevoked)
		})
	}
}

func TestDiscoverErrors(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		issuer   func(*ssftest.Transmitter) string
		token    string
		name     string
		contains string
		opts     []ssftest.Option
	}{
		{
			name:     "no configuration endpoint",
			opts:     []ssftest.Option{ssftest.WithoutConfigurationEndpoint()},
			contains: "configuration_endpoint is missing",
		},
		{
			name:     "no jwks_uri",
			opts:     []ssftest.Option{ssftest.WithoutJWKSURI()},
			contains: "jwks_uri is missing",
		},
		{
			name:     "several streams",
			opts:     []ssftest.Option{ssftest.WithStreams(2)},
			contains: "returned 2 streams",
		},
		{
			name:     "no stream",
			opts:     []ssftest.Option{ssftest.WithStreams(0)},
			contains: "has no stream",
		},
		{
			name:     "push stream",
			opts:     []ssftest.Option{ssftest.WithPushDelivery()},
			contains: "poll delivery",
		},
		{
			name:     "wrong token",
			token:    "wrong",
			contains: "unexpected HTTP status 401",
		},
		{
			name:     "issuer mismatch",
			issuer:   func(transmitter *ssftest.Transmitter) string { return transmitter.Issuer() + "/" },
			contains: "does not match",
		},
		{
			name:     "metadata not found",
			issuer:   func(transmitter *ssftest.Transmitter) string { return transmitter.Issuer() + "/realms/other" },
			contains: "unexpected HTTP status 404",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			transmitter := ssftest.New(t, tc.opts...)

			issuer := transmitter.Issuer()
			if tc.issuer != nil {
				issuer = tc.issuer(transmitter)
			}

			token := transmitter.Token()
			if tc.token != "" {
				token = tc.token
			}

			_, err := ssf.Discover(t.Context(), transmitter.Client(), mustParseURL(t, issuer), token)
			require.ErrorContains(t, err, tc.contains)
		})
	}
}

func TestDiscoverUnreachable(t *testing.T) {
	t.Parallel()

	_, err := ssf.Discover(t.Context(), http.DefaultClient, mustParseURL(t, "https://127.0.0.1:1"), "token")
	require.ErrorContains(t, err, "fetch transmitter configuration metadata")
}
