package ssftest_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/ssf/ssftest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// result is a response with its body already read and closed.
type result struct {
	header http.Header
	body   []byte
	status int
}

func doRequest(tb testing.TB, transmitter *ssftest.Transmitter, method, url, token string, body any) result {
	tb.Helper()

	var reader io.Reader

	if body != nil {
		payload, err := json.Marshal(body)
		require.NoError(tb, err)

		reader = bytes.NewReader(payload)
	}

	req, err := http.NewRequestWithContext(tb.Context(), method, url, reader)
	require.NoError(tb, err)

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := transmitter.Client().Do(req)
	require.NoError(tb, err)

	defer func() {
		_ = resp.Body.Close()
	}()

	respBody, err := io.ReadAll(resp.Body)
	require.NoError(tb, err)

	return result{header: resp.Header, body: respBody, status: resp.StatusCode}
}

func getJSON(tb testing.TB, transmitter *ssftest.Transmitter, url, token string, target any) result {
	tb.Helper()

	resp := doRequest(tb, transmitter, http.MethodGet, url, token, nil)
	if resp.status == http.StatusOK {
		require.NoError(tb, json.Unmarshal(resp.body, target), string(resp.body))
	}

	return resp
}

//nolint:tagliatelle // RFC 8936 member names.
type pollResponse struct {
	Sets          map[string]string `json:"sets"`
	MoreAvailable bool              `json:"moreAvailable"`
}

func poll(tb testing.TB, transmitter *ssftest.Transmitter, request map[string]any) pollResponse {
	tb.Helper()

	resp := doRequest(tb, transmitter, http.MethodPost, transmitter.PollEndpoint(), transmitter.Token(), request)
	require.Equal(tb, http.StatusOK, resp.status, string(resp.body))

	var response pollResponse
	require.NoError(tb, json.Unmarshal(resp.body, &response), string(resp.body))

	return response
}

// verify checks token against the transmitter's JWK Set and returns its header and claims.
func verify(tb testing.TB, transmitter *ssftest.Transmitter, token string) (jose.Header, map[string]any, error) {
	tb.Helper()

	var keySet jose.JSONWebKeySet

	resp := getJSON(tb, transmitter, transmitter.JWKSURI(), "", &keySet)
	require.Equal(tb, http.StatusOK, resp.status)

	jws, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(tb, err)

	header := jws.Signatures[0].Header

	keys := keySet.Key(header.KeyID)
	if len(keys) == 0 {
		return header, nil, jose.ErrUnsupportedKeyType
	}

	payload, err := jws.Verify(keys[0])
	if err != nil {
		return header, nil, err
	}

	var claims map[string]any
	require.NoError(tb, json.Unmarshal(payload, &claims))

	return header, claims, nil
}

func TestMetadata(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name         string
		wantSuffix   string
		wantIssuer   string
		otherPath    string
		opts         []ssftest.Option
		wantConfig   bool
		wantJWKSURI  bool
		otherPresent bool
	}{
		{
			name:        "root issuer",
			wantSuffix:  "/.well-known/ssf-configuration",
			wantConfig:  true,
			wantJWKSURI: true,
		},
		{
			name:        "issuer path inserted after the host",
			opts:        []ssftest.Option{ssftest.WithIssuerPath("realms/vpn/")},
			wantSuffix:  "/.well-known/ssf-configuration/realms/vpn",
			wantIssuer:  "/realms/vpn",
			wantConfig:  true,
			wantJWKSURI: true,
			otherPath:   "/realms/vpn/.well-known/ssf-configuration",
		},
		{
			name:        "issuer path appended",
			opts:        []ssftest.Option{ssftest.WithIssuerPath("/realms/vpn"), ssftest.WithMetadataLocation(ssftest.MetadataAppended)},
			wantSuffix:  "/realms/vpn/.well-known/ssf-configuration",
			wantIssuer:  "/realms/vpn",
			wantConfig:  true,
			wantJWKSURI: true,
			otherPath:   "/.well-known/ssf-configuration/realms/vpn",
		},
		{
			name:        "without configuration endpoint and jwks uri",
			opts:        []ssftest.Option{ssftest.WithoutConfigurationEndpoint(), ssftest.WithoutJWKSURI()},
			wantSuffix:  "/.well-known/ssf-configuration",
			wantConfig:  false,
			wantJWKSURI: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			transmitter := ssftest.New(t, tc.opts...)

			require.True(t, strings.HasPrefix(transmitter.Issuer(), "https://"))
			require.True(t, strings.HasSuffix(transmitter.Issuer(), tc.wantIssuer))
			require.True(t, strings.HasSuffix(transmitter.MetadataURL(), tc.wantSuffix), transmitter.MetadataURL())

			var metadata map[string]any

			resp := getJSON(t, transmitter, transmitter.MetadataURL(), "", &metadata)
			require.Equal(t, http.StatusOK, resp.status)

			assert.Equal(t, "1_0", metadata["spec_version"])
			assert.Equal(t, transmitter.Issuer(), metadata["issuer"])
			assert.Equal(t, []any{ssftest.DeliveryMethodPoll}, metadata["delivery_methods_supported"])

			if tc.wantConfig {
				assert.Equal(t, transmitter.ConfigurationEndpoint(), metadata["configuration_endpoint"])
			} else {
				assert.NotContains(t, metadata, "configuration_endpoint")
			}

			if tc.wantJWKSURI {
				assert.Equal(t, transmitter.JWKSURI(), metadata["jwks_uri"])
			} else {
				assert.NotContains(t, metadata, "jwks_uri")
			}

			if tc.otherPath != "" {
				otherURL := strings.TrimSuffix(transmitter.MetadataURL(), tc.wantSuffix) + tc.otherPath
				resp := doRequest(t, transmitter, http.MethodGet, otherURL, "", nil)
				assert.Equal(t, http.StatusNotFound, resp.status)
			}
		})
	}
}

func TestStreams(t *testing.T) {
	t.Parallel()

	t.Run("requires the bearer token", func(t *testing.T) {
		t.Parallel()

		transmitter := ssftest.New(t)

		for _, token := range []string{"", "wrong"} {
			resp := doRequest(t, transmitter, http.MethodGet, transmitter.ConfigurationEndpoint(), token, nil)
			assert.Equal(t, http.StatusUnauthorized, resp.status)
			assert.Contains(t, resp.header.Get("WWW-Authenticate"), "Bearer")
		}
	})

	t.Run("lists the poll stream", func(t *testing.T) {
		t.Parallel()

		transmitter := ssftest.New(t, ssftest.WithToken("secret"))
		require.Equal(t, "secret", transmitter.Token())
		require.Len(t, transmitter.StreamIDs(), 1)

		var streams []map[string]any

		resp := getJSON(t, transmitter, transmitter.ConfigurationEndpoint(), "secret", &streams)
		require.Equal(t, http.StatusOK, resp.status)
		require.Len(t, streams, 1)

		stream := streams[0]
		assert.Equal(t, transmitter.StreamIDs()[0], stream["stream_id"])
		assert.Equal(t, transmitter.Issuer(), stream["iss"])
		assert.Equal(t, ssftest.DefaultAudience, stream["aud"])
		assert.Equal(t, map[string]any{
			"method":       ssftest.DeliveryMethodPoll,
			"endpoint_url": transmitter.PollEndpoint(),
		}, stream["delivery"])
		assert.Equal(t, []any{ssftest.EventTypeSessionRevoked}, stream["events_delivered"])
	})

	t.Run("reads one stream by id", func(t *testing.T) {
		t.Parallel()

		transmitter := ssftest.New(t, ssftest.WithStreams(2), ssftest.WithAudience("https://a.example.com", "https://b.example.com"))
		streamIDs := transmitter.StreamIDs()
		require.Len(t, streamIDs, 2)
		assert.Equal(t, []string{"https://a.example.com", "https://b.example.com"}, transmitter.Audience())

		var streams []map[string]any

		resp := getJSON(t, transmitter, transmitter.ConfigurationEndpoint(), transmitter.Token(), &streams)
		require.Equal(t, http.StatusOK, resp.status)
		require.Len(t, streams, 2)

		var stream map[string]any

		resp = getJSON(t, transmitter, transmitter.ConfigurationEndpoint()+"?stream_id="+streamIDs[1], transmitter.Token(), &stream)
		require.Equal(t, http.StatusOK, resp.status)
		assert.Equal(t, streamIDs[1], stream["stream_id"])
		assert.Equal(t, []any{"https://a.example.com", "https://b.example.com"}, stream["aud"])

		resp = getJSON(t, transmitter, transmitter.ConfigurationEndpoint()+"?stream_id=unknown", transmitter.Token(), &stream)
		assert.Equal(t, http.StatusNotFound, resp.status)
	})

	t.Run("push stream has no poll endpoint", func(t *testing.T) {
		t.Parallel()

		transmitter := ssftest.New(t, ssftest.WithPushDelivery())

		var streams []map[string]any

		resp := getJSON(t, transmitter, transmitter.ConfigurationEndpoint(), transmitter.Token(), &streams)
		require.Equal(t, http.StatusOK, resp.status)
		require.Len(t, streams, 1)
		assert.Equal(t, map[string]any{"method": ssftest.DeliveryMethodPush}, streams[0]["delivery"])
	})
}

func TestSign(t *testing.T) {
	t.Parallel()

	transmitter := ssftest.New(t, ssftest.WithIssuerPath("/realms/vpn"))
	subject := ssftest.UserSession(ssftest.IssSub(transmitter.Issuer(), "user-1"), ssftest.Opaque("session-1"))

	set := transmitter.NewSessionRevoked(subject)
	require.NotEmpty(t, set.JTI)
	require.NotEmpty(t, set.TXN)

	header, claims, err := verify(t, transmitter, transmitter.Sign(t, set))
	require.NoError(t, err)

	assert.Equal(t, ssftest.SETType, header.ExtraHeaders[jose.HeaderType])
	assert.NotEmpty(t, header.KeyID)
	assert.Equal(t, string(jose.RS256), header.Algorithm)

	assert.Equal(t, transmitter.Issuer(), claims["iss"])
	assert.Equal(t, set.JTI, claims["jti"])
	assert.Equal(t, ssftest.DefaultAudience, claims["aud"])
	assert.InDelta(t, time.Now().Unix(), claims["iat"], 5)
	assert.NotContains(t, claims, "exp")
	assert.NotContains(t, claims, "sub")
	assert.Equal(t, map[string]any{
		"format":  "complex",
		"user":    map[string]any{"format": "iss_sub", "iss": transmitter.Issuer(), "sub": "user-1"},
		"session": map[string]any{"format": "opaque", "id": "session-1"},
	}, claims["sub_id"])

	events, ok := claims["events"].(map[string]any)
	require.True(t, ok)
	require.Contains(t, events, ssftest.EventTypeSessionRevoked)

	t.Run("header overrides", func(t *testing.T) {
		t.Parallel()

		header, _, err := verify(t, transmitter, transmitter.Sign(t, set, ssftest.WithType("JWT")))
		require.NoError(t, err)
		assert.Equal(t, "JWT", header.ExtraHeaders[jose.HeaderType])

		header, _, err = verify(t, transmitter, transmitter.Sign(t, set, ssftest.WithType("")))
		require.NoError(t, err)
		assert.NotContains(t, header.ExtraHeaders, jose.HeaderType)

		header, _, err = verify(t, transmitter, transmitter.Sign(t, set, ssftest.WithKeyID("unknown")))
		require.Error(t, err)
		assert.Equal(t, "unknown", header.KeyID)
	})

	t.Run("unpublished key fails verification", func(t *testing.T) {
		t.Parallel()

		_, _, err := verify(t, transmitter, transmitter.Sign(t, set, ssftest.WithUnpublishedKey(t)))
		require.Error(t, err)
	})

	t.Run("arbitrary claims", func(t *testing.T) {
		t.Parallel()

		_, claims, err := verify(t, transmitter, transmitter.Sign(t, map[string]any{"iss": "x", "exp": 1}))
		require.NoError(t, err)
		assert.Equal(t, map[string]any{"iss": "x", "exp": float64(1)}, claims)
	})
}

func TestSubjects(t *testing.T) {
	t.Parallel()

	assert.Equal(t, ssftest.Subject{"format": "email", "email": "user@example.com"}, ssftest.Email("user@example.com"))
	assert.Equal(t, ssftest.Subject{
		"format": "complex",
		"user":   ssftest.Subject{"format": "email", "email": "user@example.com"},
	}, ssftest.Complex(map[string]ssftest.Subject{"user": ssftest.Email("user@example.com")}))

	payload, err := json.Marshal(ssftest.Audience{"a", "b"})
	require.NoError(t, err)
	assert.JSONEq(t, `["a","b"]`, string(payload))

	payload, err = json.Marshal(ssftest.Audience{"a"})
	require.NoError(t, err)
	assert.JSONEq(t, `"a"`, string(payload))

	var audience ssftest.Audience

	require.NoError(t, json.Unmarshal([]byte(`"a"`), &audience))
	assert.Equal(t, ssftest.Audience{"a"}, audience)
	require.NoError(t, json.Unmarshal([]byte(`["a","b"]`), &audience))
	assert.Equal(t, ssftest.Audience{"a", "b"}, audience)
	require.Error(t, json.Unmarshal([]byte(`1`), &audience))

	transmitter := ssftest.New(t)
	set := transmitter.NewSET(ssftest.Email("user@example.com"), ssftest.EventTypeCredentialChange, nil)
	assert.Equal(t, map[string]any{ssftest.EventTypeCredentialChange: map[string]any{}}, set.Events)
}

func TestRotateKey(t *testing.T) {
	t.Parallel()

	transmitter := ssftest.New(t)
	set := transmitter.NewSessionRevoked(ssftest.IssSub("iss", "sub"))

	oldToken := transmitter.Sign(t, set)
	transmitter.RotateKey(t)
	newToken := transmitter.Sign(t, set)

	oldHeader, _, err := verify(t, transmitter, oldToken)
	require.NoError(t, err)

	newHeader, _, err := verify(t, transmitter, newToken)
	require.NoError(t, err)

	assert.NotEqual(t, oldHeader.KeyID, newHeader.KeyID)

	var keySet jose.JSONWebKeySet

	getJSON(t, transmitter, transmitter.JWKSURI(), "", &keySet)
	require.Len(t, keySet.Keys, 2)

	for _, key := range keySet.Keys {
		assert.True(t, key.IsPublic())
		assert.Equal(t, string(jose.RS256), key.Algorithm)
		assert.Equal(t, "sig", key.Use)
	}
}

func TestPoll(t *testing.T) {
	t.Parallel()

	t.Run("requires the bearer token", func(t *testing.T) {
		t.Parallel()

		transmitter := ssftest.New(t)

		resp := doRequest(t, transmitter, http.MethodPost, transmitter.PollEndpoint(), "wrong", map[string]any{})
		assert.Equal(t, http.StatusUnauthorized, resp.status)
		assert.Empty(t, transmitter.PollRequests())
	})

	t.Run("rejects invalid requests", func(t *testing.T) {
		t.Parallel()

		transmitter := ssftest.New(t)

		resp := doRequest(t, transmitter, http.MethodPost, transmitter.PollEndpoint(), transmitter.Token(), "not an object")
		assert.Equal(t, http.StatusBadRequest, resp.status)

		resp = doRequest(t, transmitter, http.MethodPost, transmitter.PollEndpoint(), transmitter.Token(), map[string]any{"maxEvents": -1})
		assert.Equal(t, http.StatusBadRequest, resp.status)
	})

	t.Run("delivers, redelivers and settles SETs", func(t *testing.T) {
		t.Parallel()

		transmitter := ssftest.New(t)

		response := poll(t, transmitter, map[string]any{"returnImmediately": true})
		assert.Empty(t, response.Sets)
		assert.False(t, response.MoreAvailable)

		first := transmitter.EmitSessionRevoked(t, ssftest.IssSub(transmitter.Issuer(), "user-1"))
		second := transmitter.Emit(t, transmitter.NewSessionRevoked(ssftest.IssSub(transmitter.Issuer(), "user-2")))
		third := transmitter.EmitSessionRevoked(t, ssftest.IssSub(transmitter.Issuer(), "user-3"))
		transmitter.EmitToken("raw", "not-a-jwt")
		require.Equal(t, []string{first, second, third, "raw"}, transmitter.Pending())

		response = poll(t, transmitter, map[string]any{"maxEvents": 1})
		require.Len(t, response.Sets, 1)
		require.Contains(t, response.Sets, first)
		assert.True(t, response.MoreAvailable)

		_, claims, err := verify(t, transmitter, response.Sets[first])
		require.NoError(t, err)
		assert.Equal(t, first, claims["jti"])

		// Not acknowledged, so it is delivered again.
		response = poll(t, transmitter, map[string]any{"maxEvents": 2})
		assert.ElementsMatch(t, []string{first, second}, keys(response.Sets))
		assert.True(t, response.MoreAvailable)

		response = poll(t, transmitter, map[string]any{
			"ack":     []string{first, second},
			"setErrs": map[string]any{third: map[string]string{"err": "invalid_key", "description": "unknown kid"}},
		})
		assert.Equal(t, map[string]string{"raw": "not-a-jwt"}, response.Sets)
		assert.False(t, response.MoreAvailable)

		// maxEvents 0 only acknowledges.
		response = poll(t, transmitter, map[string]any{"ack": []string{"raw", first}, "maxEvents": 0})
		assert.Empty(t, response.Sets)

		assert.Empty(t, transmitter.Pending())
		assert.Equal(t, []string{first, second, "raw"}, transmitter.Acked())
		assert.Equal(t, map[string]ssftest.SetErr{third: {Err: "invalid_key", Description: "unknown kid"}}, transmitter.SetErrs())

		requests := transmitter.PollRequests()
		require.Len(t, requests, 5)
		assert.True(t, requests[0].ReturnImmediately)
		require.NotNil(t, requests[1].MaxEvents)
		assert.Equal(t, 1, *requests[1].MaxEvents)
		assert.Equal(t, []string{first, second}, requests[3].Ack)
	})

	t.Run("injected failures", func(t *testing.T) {
		t.Parallel()

		transmitter := ssftest.New(t)
		jti := transmitter.EmitSessionRevoked(t, ssftest.Email("user@example.com"))

		transmitter.FailNextPoll(http.StatusTooManyRequests, http.Header{"Retry-After": []string{"2"}})
		transmitter.FailNextPoll(http.StatusServiceUnavailable, nil)

		resp := doRequest(t, transmitter, http.MethodPost, transmitter.PollEndpoint(), transmitter.Token(), map[string]any{"ack": []string{jti}})
		assert.Equal(t, http.StatusTooManyRequests, resp.status)
		assert.Equal(t, "2", resp.header.Get("Retry-After"))

		resp = doRequest(t, transmitter, http.MethodPost, transmitter.PollEndpoint(), transmitter.Token(), map[string]any{"ack": []string{jti}})
		assert.Equal(t, http.StatusServiceUnavailable, resp.status)

		// The failed requests did not acknowledge the SET.
		assert.Equal(t, []string{jti}, transmitter.Pending())
		assert.Empty(t, transmitter.Acked())
		assert.Len(t, transmitter.PollRequests(), 2)

		response := poll(t, transmitter, map[string]any{})
		assert.Contains(t, response.Sets, jti)
	})
}

func TestLongPoll(t *testing.T) {
	t.Parallel()

	t.Run("returns when a SET arrives", func(t *testing.T) {
		t.Parallel()

		transmitter := ssftest.New(t, ssftest.WithLongPollHold(time.Minute))
		done := make(chan pollResult, 1)

		go func() {
			done <- pollAsync(t.Context(), transmitter)
		}()

		require.Eventually(t, func() bool {
			return len(transmitter.PollRequests()) == 1
		}, 5*time.Second, 10*time.Millisecond)

		jti := transmitter.EmitSessionRevoked(t, ssftest.Email("user@example.com"))

		select {
		case result := <-done:
			require.NoError(t, result.err)
			assert.Contains(t, result.response.Sets, jti)
		case <-time.After(10 * time.Second):
			t.Fatal("long poll did not return after Emit")
		}
	})

	t.Run("returns empty after the hold", func(t *testing.T) {
		t.Parallel()

		transmitter := ssftest.New(t, ssftest.WithLongPollHold(50*time.Millisecond))

		start := time.Now()
		response := poll(t, transmitter, map[string]any{})

		assert.Empty(t, response.Sets)
		assert.GreaterOrEqual(t, time.Since(start), 50*time.Millisecond)
	})

	t.Run("returnImmediately and ack-only requests are not held", func(t *testing.T) {
		t.Parallel()

		transmitter := ssftest.New(t, ssftest.WithLongPollHold(time.Minute))

		assert.Empty(t, poll(t, transmitter, map[string]any{"returnImmediately": true}).Sets)
		assert.Empty(t, poll(t, transmitter, map[string]any{"maxEvents": 0}).Sets)
	})
}

type pollResult struct {
	err      error
	response pollResponse
}

// pollAsync polls without test assertions, so it can run outside the test goroutine.
func pollAsync(ctx context.Context, transmitter *ssftest.Transmitter) pollResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, transmitter.PollEndpoint(), strings.NewReader("{}"))
	if err != nil {
		return pollResult{err: err}
	}

	req.Header.Set("Authorization", "Bearer "+transmitter.Token())

	resp, err := transmitter.Client().Do(req)
	if err != nil {
		return pollResult{err: err}
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return pollResult{err: errors.New(resp.Status)}
	}

	var response pollResponse

	err = json.NewDecoder(resp.Body).Decode(&response)

	return pollResult{response: response, err: err}
}

func keys(sets map[string]string) []string {
	jtis := make([]string, 0, len(sets))
	for jti := range sets {
		jtis = append(jtis, jti)
	}

	return jtis
}
