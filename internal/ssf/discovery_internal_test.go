package ssf

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMetadataValidate(t *testing.T) {
	t.Parallel()

	const issuer = "https://idp.example.com"

	valid := TransmitterMetadata{
		Issuer:                issuer,
		JWKSURI:               issuer + "/jwks",
		ConfigurationEndpoint: issuer + "/streams",
	}
	require.NoError(t, valid.validate(issuer))

	for name, modify := range map[string]func(*TransmitterMetadata){
		"http jwks_uri":               func(m *TransmitterMetadata) { m.JWKSURI = "http://idp.example.com/jwks" },
		"http configuration_endpoint": func(m *TransmitterMetadata) { m.ConfigurationEndpoint = "http://idp.example.com/streams" },
		"jwks_uri without host":       func(m *TransmitterMetadata) { m.JWKSURI = "https:///jwks" },
		"malformed jwks_uri":          func(m *TransmitterMetadata) { m.JWKSURI = "https://idp.example.com/%zz" },
	} {
		metadata := valid
		modify(&metadata)
		require.Error(t, metadata.validate(issuer), name)
	}
}

func TestStreamValidate(t *testing.T) {
	t.Parallel()

	const issuer = "https://idp.example.com"

	valid := StreamConfiguration{Issuer: issuer, Audience: audience{"https://vpn.example.com"}}
	valid.Delivery.Method = DeliveryMethodPoll
	valid.Delivery.EndpointURL = issuer + "/poll"
	require.NoError(t, valid.validate(issuer))

	for name, modify := range map[string]func(*StreamConfiguration){
		"other issuer":     func(s *StreamConfiguration) { s.Issuer = "https://other.example.com" },
		"no audience":      func(s *StreamConfiguration) { s.Audience = nil },
		"http endpoint":    func(s *StreamConfiguration) { s.Delivery.EndpointURL = "http://idp.example.com/poll" },
		"missing endpoint": func(s *StreamConfiguration) { s.Delivery.EndpointURL = "" },
	} {
		stream := valid
		modify(&stream)
		require.Error(t, stream.validate(issuer), name)
	}
}

func TestDecodeStreams(t *testing.T) {
	t.Parallel()

	streams, err := decodeStreams([]byte(`{"stream_id":"a"}`))
	require.NoError(t, err)
	assert.Len(t, streams, 1)

	streams, err = decodeStreams([]byte(`[{"stream_id":"a"},{"stream_id":"b"}]`))
	require.NoError(t, err)
	assert.Len(t, streams, 2)

	_, err = decodeStreams([]byte(`"a"`))
	require.Error(t, err)
}

func TestRetryAfter(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 15, 8, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		value  string
		status int
		want   time.Duration
	}{
		{status: http.StatusTooManyRequests, value: "120", want: 2 * time.Minute},
		{status: http.StatusServiceUnavailable, value: now.Add(time.Minute).Format(http.TimeFormat), want: time.Minute},
		{status: http.StatusServiceUnavailable, value: now.Add(-time.Minute).Format(http.TimeFormat), want: 0},
		{status: http.StatusTooManyRequests, value: "-5", want: 0},
		{status: http.StatusTooManyRequests, value: "soon", want: 0},
		{status: http.StatusTooManyRequests, want: 0},
		{status: http.StatusInternalServerError, value: "120", want: 0},
	} {
		resp := &http.Response{StatusCode: tc.status, Header: http.Header{}}
		if tc.value != "" {
			resp.Header.Set("Retry-After", tc.value)
		}

		assert.Equal(t, tc.want, retryAfter(resp, now), tc.value)
	}
}
