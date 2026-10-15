package ssf

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

const maxPollResponseSize = 16 << 20

// StatusError is a non-success HTTP response from the transmitter.
type StatusError struct {
	URL        string
	StatusCode int
	// RetryAfter is the Retry-After delay of a 429 or 503 response, if any.
	RetryAfter time.Duration
}

// Error implements the error interface.
func (e *StatusError) Error() string {
	return fmt.Sprintf("%s: unexpected HTTP status %d %s", e.URL, e.StatusCode, http.StatusText(e.StatusCode))
}

// SetErr is the error a receiver reports for a SET in the setErrs member of a
// poll request (RFC 8936, section 2.4).
type SetErr struct {
	Err         string `json:"err"`
	Description string `json:"description"`
}

// pollRequest is an RFC 8936 poll request.
//
//nolint:tagliatelle // RFC 8936 member names.
type pollRequest struct {
	SetErrs           map[string]SetErr `json:"setErrs,omitempty"`
	Ack               []string          `json:"ack,omitempty"`
	MaxEvents         int               `json:"maxEvents"`
	ReturnImmediately bool              `json:"returnImmediately"`
}

// pollResponse is an RFC 8936 poll response.
//
//nolint:tagliatelle // RFC 8936 member names.
type pollResponse struct {
	Sets          map[string]string `json:"sets"`
	MoreAvailable bool              `json:"moreAvailable"`
}

// poll sends one poll request to endpoint.
func poll(ctx context.Context, client *http.Client, endpoint, token string, request pollRequest) (pollResponse, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return pollResponse{}, fmt.Errorf("encode poll request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return pollResponse{}, fmt.Errorf("create poll request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return pollResponse{}, fmt.Errorf("poll %s: %w", endpoint, err)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxDiscoveryResponseSize))

		return pollResponse{}, &StatusError{
			URL:        endpoint,
			StatusCode: resp.StatusCode,
			RetryAfter: retryAfter(resp, time.Now()),
		}
	}

	var response pollResponse

	if err = json.NewDecoder(io.LimitReader(resp.Body, maxPollResponseSize)).Decode(&response); err != nil {
		return pollResponse{}, fmt.Errorf("decode poll response: %w", err)
	}

	return response, nil
}

// retryAfter returns the Retry-After delay of a 429 or 503 response, or 0.
func retryAfter(resp *http.Response, now time.Time) time.Duration {
	if resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode != http.StatusServiceUnavailable {
		return 0
	}

	value := resp.Header.Get("Retry-After")
	if value == "" {
		return 0
	}

	if seconds, err := strconv.Atoi(value); err == nil {
		return max(time.Duration(seconds)*time.Second, 0)
	}

	if date, err := http.ParseTime(value); err == nil {
		return max(date.Sub(now), 0)
	}

	return 0
}
