package ssf

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"
)

const (
	// WellKnownPath is the well-known path of the transmitter configuration
	// metadata (SSF 1.0, section 7.2).
	WellKnownPath = "/.well-known/ssf-configuration"

	// DeliveryMethodPoll is the delivery method URI of RFC 8936 poll delivery.
	DeliveryMethodPoll = "urn:ietf:rfc:8936"

	maxDiscoveryResponseSize = 1 << 20
)

// TransmitterMetadata is the part of the transmitter configuration metadata
// (SSF 1.0, section 7.1) the receiver uses.
//
//nolint:tagliatelle // SSF 1.0 member names.
type TransmitterMetadata struct {
	Issuer                   string   `json:"issuer"`
	JWKSURI                  string   `json:"jwks_uri"`
	ConfigurationEndpoint    string   `json:"configuration_endpoint"`
	DeliveryMethodsSupported []string `json:"delivery_methods_supported"`
	CriticalSubjectMembers   []string `json:"critical_subject_members"`
}

// StreamConfiguration is the part of a stream configuration (SSF 1.0,
// section 8.1.1) the receiver uses.
//
//nolint:tagliatelle // SSF 1.0 member names.
type StreamConfiguration struct {
	Delivery struct {
		Method      string `json:"method"`
		EndpointURL string `json:"endpoint_url"`
	} `json:"delivery"`
	StreamID        string   `json:"stream_id"`
	Issuer          string   `json:"iss"`
	Audience        audience `json:"aud"`
	EventsDelivered []string `json:"events_delivered"`
}

// Discovery is everything the receiver learns from the transmitter at startup.
type Discovery struct {
	Stream   StreamConfiguration
	Metadata TransmitterMetadata
}

// Discover reads the transmitter configuration metadata of issuer, checks
// that its JWK Set can be fetched, and reads the one stream configuration
// the access tokens from tokens can see. Every discovered URL must use https.
func Discover(ctx context.Context, client *http.Client, issuer *url.URL, tokens oauth2.TokenSource) (Discovery, error) {
	metadata, err := fetchMetadata(ctx, client, issuer)
	if err != nil {
		return Discovery{}, err
	}

	if err = checkKeySet(ctx, client, metadata.JWKSURI); err != nil {
		return Discovery{}, err
	}

	stream, err := fetchStream(ctx, client, metadata, tokens)
	if err != nil {
		return Discovery{}, err
	}

	return Discovery{Metadata: metadata, Stream: stream}, nil
}

// MetadataURLs returns the locations of the transmitter configuration
// metadata of issuer, in the order they are tried: the well-known path
// inserted between host and path as SSF 1.0 requires, then appended to the
// path as OpenID Connect discovery does. An issuer without a path has one
// location.
func MetadataURLs(issuer *url.URL) []string {
	path := strings.TrimSuffix(issuer.Path, "/")

	inserted := *issuer
	inserted.Path = WellKnownPath + path
	inserted.RawPath = ""

	if path == "" {
		return []string{inserted.String()}
	}

	appended := *issuer
	appended.Path = path + WellKnownPath
	appended.RawPath = ""

	return []string{inserted.String(), appended.String()}
}

func fetchMetadata(ctx context.Context, client *http.Client, issuer *url.URL) (TransmitterMetadata, error) {
	var errs []error

	for _, location := range MetadataURLs(issuer) {
		var metadata TransmitterMetadata

		if err := getJSON(ctx, client, location, nil, &metadata); err != nil {
			errs = append(errs, err)

			continue
		}

		if err := metadata.validate(issuer.String()); err != nil {
			return TransmitterMetadata{}, fmt.Errorf("transmitter configuration metadata %s: %w", location, err)
		}

		return metadata, nil
	}

	return TransmitterMetadata{}, fmt.Errorf("fetch transmitter configuration metadata: %w", errors.Join(errs...))
}

func (m TransmitterMetadata) validate(issuer string) error {
	if m.Issuer != issuer {
		return fmt.Errorf("issuer %q does not match %q", m.Issuer, issuer)
	}

	if err := requireHTTPS("jwks_uri", m.JWKSURI); err != nil {
		return err
	}

	if m.ConfigurationEndpoint == "" {
		return errors.New("configuration_endpoint is missing; transmitters without stream configuration are not supported")
	}

	if err := requireHTTPS("configuration_endpoint", m.ConfigurationEndpoint); err != nil {
		return err
	}

	if len(m.DeliveryMethodsSupported) > 0 && !slices.Contains(m.DeliveryMethodsSupported, DeliveryMethodPoll) {
		return fmt.Errorf("delivery_methods_supported %q does not contain poll delivery %q", m.DeliveryMethodsSupported, DeliveryMethodPoll)
	}

	return nil
}

// checkKeySet fetches the JWK Set once, so a broken jwks_uri fails at startup
// instead of on the first event.
func checkKeySet(ctx context.Context, client *http.Client, jwksURI string) error {
	var keySet jose.JSONWebKeySet

	if err := getJSON(ctx, client, jwksURI, nil, &keySet); err != nil {
		return fmt.Errorf("fetch transmitter JWK Set: %w", err)
	}

	if len(keySet.Keys) == 0 {
		return fmt.Errorf("transmitter JWK Set %s has no keys", jwksURI)
	}

	return nil
}

func fetchStream(ctx context.Context, client *http.Client, metadata TransmitterMetadata, tokens oauth2.TokenSource) (StreamConfiguration, error) {
	var raw json.RawMessage

	if err := getJSON(ctx, client, metadata.ConfigurationEndpoint, tokens, &raw); err != nil {
		return StreamConfiguration{}, fmt.Errorf("fetch stream configuration: %w", err)
	}

	streams, err := decodeStreams(raw)
	if err != nil {
		return StreamConfiguration{}, fmt.Errorf("decode stream configuration: %w", err)
	}

	switch len(streams) {
	case 0:
		return StreamConfiguration{}, errors.New("the transmitter has no stream for this receiver; create one first")
	case 1:
	default:
		return StreamConfiguration{}, fmt.Errorf("the transmitter returned %d streams for this receiver; only one is supported", len(streams))
	}

	stream := streams[0]
	if err = stream.validate(metadata.Issuer); err != nil {
		return StreamConfiguration{}, fmt.Errorf("stream %q: %w", stream.StreamID, err)
	}

	return stream, nil
}

// decodeStreams decodes a configuration endpoint response, which is a single
// stream configuration or an array of them.
func decodeStreams(raw json.RawMessage) ([]StreamConfiguration, error) {
	var streams []StreamConfiguration
	if err := json.Unmarshal(raw, &streams); err == nil {
		return streams, nil
	}

	var stream StreamConfiguration
	if err := json.Unmarshal(raw, &stream); err != nil {
		return nil, err //nolint:wrapcheck // wrapped by the caller
	}

	return []StreamConfiguration{stream}, nil
}

func (s StreamConfiguration) validate(issuer string) error {
	if s.Issuer != issuer {
		return fmt.Errorf("iss %q does not match the transmitter issuer %q", s.Issuer, issuer)
	}

	if len(s.Audience) == 0 {
		return errors.New("aud is missing")
	}

	if s.Delivery.Method != DeliveryMethodPoll {
		return fmt.Errorf("delivery method %q is not poll delivery %q", s.Delivery.Method, DeliveryMethodPoll)
	}

	return requireHTTPS("delivery.endpoint_url", s.Delivery.EndpointURL)
}

func requireHTTPS(name, value string) error {
	if value == "" {
		return fmt.Errorf("%s is missing", name)
	}

	parsed, err := url.Parse(value)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}

	if parsed.Scheme != "https" || parsed.Host == "" {
		return fmt.Errorf("%s %q must be an https URL", name, value)
	}

	return nil
}

// getJSON GETs location and decodes the JSON response into target. With a
// non-nil tokens, the request carries a bearer token from it.
func getJSON(ctx context.Context, client *http.Client, location string, tokens oauth2.TokenSource, target any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")

	if tokens != nil {
		if err = setBearerToken(req, tokens); err != nil {
			return err
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch %s: %w", location, err)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return &StatusError{URL: location, StatusCode: resp.StatusCode}
	}

	if err = json.NewDecoder(io.LimitReader(resp.Body, maxDiscoveryResponseSize)).Decode(target); err != nil {
		return fmt.Errorf("decode %s: %w", location, err)
	}

	return nil
}

// setBearerToken sets the Authorization header of req to an access token from tokens.
func setBearerToken(req *http.Request, tokens oauth2.TokenSource) error {
	token, err := tokens.Token()
	if err != nil {
		return fmt.Errorf("obtain access token for the SSF transmitter: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token.AccessToken)

	return nil
}
