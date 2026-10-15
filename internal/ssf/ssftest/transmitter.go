package ssftest

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
)

const (
	// DeliveryMethodPoll is the SSF delivery method URI for RFC 8936 poll delivery.
	DeliveryMethodPoll = "urn:ietf:rfc:8936"
	// DeliveryMethodPush is the SSF delivery method URI for RFC 8935 push delivery.
	DeliveryMethodPush = "urn:ietf:rfc:8935"

	// EventTypeSessionRevoked is the CAEP session-revoked event type.
	EventTypeSessionRevoked = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
	// EventTypeCredentialChange is the CAEP credential-change event type.
	EventTypeCredentialChange = "https://schemas.openid.net/secevent/caep/event-type/credential-change"

	// SETType is the typ header of a Security Event Token (RFC 8417).
	SETType = "secevent+jwt"

	// WellKnownPath is the well-known path of the SSF transmitter configuration metadata.
	WellKnownPath = "/.well-known/ssf-configuration"

	// DefaultToken is the bearer token the transmitter accepts unless WithToken is used.
	DefaultToken = "ssf-test-token"
	// DefaultAudience is the stream audience unless WithAudience is used.
	DefaultAudience = "https://vpn.example.com"

	rsaKeyBits = 2048
)

// MetadataLocation selects where the transmitter serves its configuration
// metadata when the issuer has a path.
type MetadataLocation int

const (
	// MetadataInserted serves the metadata at https://host/.well-known/ssf-configuration/<path>,
	// as SSF 1.0 requires.
	MetadataInserted MetadataLocation = iota
	// MetadataAppended serves the metadata at https://host/<path>/.well-known/ssf-configuration,
	// as transmitters that follow the OpenID Connect discovery layout do.
	MetadataAppended
)

// Option configures a Transmitter.
type Option func(*options)

type options struct {
	issuerPath               string
	token                    string
	deliveryMethodOfStream   string
	audience                 []string
	deliveryMethodsSupported []string
	streams                  int
	longPollHold             time.Duration
	metadataLocation         MetadataLocation
	noConfigurationEndpoint  bool
	noJWKSURI                bool
}

// WithIssuerPath adds a path to the issuer, for example "/realms/vpn".
func WithIssuerPath(path string) Option {
	return func(o *options) {
		o.issuerPath = ""

		if trimmed := strings.Trim(path, "/"); trimmed != "" {
			o.issuerPath = "/" + trimmed
		}
	}
}

// WithMetadataLocation selects where the metadata is served when the issuer has a path.
func WithMetadataLocation(location MetadataLocation) Option {
	return func(o *options) {
		o.metadataLocation = location
	}
}

// WithToken sets the bearer token the stream and poll endpoints accept.
func WithToken(token string) Option {
	return func(o *options) {
		o.token = token
	}
}

// WithAudience sets the aud of the stream and of every SET built by NewSET.
func WithAudience(audience ...string) Option {
	return func(o *options) {
		o.audience = audience
	}
}

// WithStreams sets how many streams the token can read. The default is 1.
func WithStreams(streams int) Option {
	return func(o *options) {
		o.streams = streams
	}
}

// WithoutConfigurationEndpoint omits configuration_endpoint from the metadata,
// which SSF 1.0 allows.
func WithoutConfigurationEndpoint() Option {
	return func(o *options) {
		o.noConfigurationEndpoint = true
	}
}

// WithoutJWKSURI omits jwks_uri from the metadata, which SSF 1.0 allows.
func WithoutJWKSURI() Option {
	return func(o *options) {
		o.noJWKSURI = true
	}
}

// WithPushDelivery configures the stream for push delivery, so it has no poll endpoint.
func WithPushDelivery() Option {
	return func(o *options) {
		o.deliveryMethodOfStream = DeliveryMethodPush
		o.deliveryMethodsSupported = []string{DeliveryMethodPush}
	}
}

// WithLongPollHold makes the poll endpoint hold a request without events for
// up to hold, unless the receiver sets returnImmediately. Without it, the
// endpoint always answers at once.
func WithLongPollHold(hold time.Duration) Option {
	return func(o *options) {
		o.longPollHold = hold
	}
}

// SetErr is an error a receiver reported for a SET in the setErrs member of a
// poll request (RFC 8936, section 2.4).
type SetErr struct {
	Err         string `json:"err"`
	Description string `json:"description"`
}

// PollRequest is a poll request the transmitter received (RFC 8936, section 2.4).
//
//nolint:tagliatelle // RFC 8936 member names.
type PollRequest struct {
	MaxEvents         *int              `json:"maxEvents,omitempty"`
	SetErrs           map[string]SetErr `json:"setErrs,omitempty"`
	Ack               []string          `json:"ack,omitempty"`
	ReturnImmediately bool              `json:"returnImmediately,omitempty"`
}

//nolint:tagliatelle // RFC 8936 member names.
type pollResponse struct {
	Sets          map[string]string `json:"sets"`
	MoreAvailable bool              `json:"moreAvailable,omitempty"`
}

type queuedSET struct {
	jti   string
	token string
}

type pollError struct {
	header http.Header
	status int
}

// Transmitter is an in-process SSF 1.0 transmitter for tests. It serves the
// configuration metadata, a JWK Set, the stream configuration endpoint and an
// RFC 8936 poll endpoint over TLS, and signs SETs with a generated RSA key.
//
// Queued SETs stay pending until a poll request acknowledges them or reports
// them in setErrs, so a SET that is delivered but not acknowledged is
// delivered again by the next poll.
type Transmitter struct {
	server       *httptest.Server
	notify       chan struct{}
	setErrs      map[string]SetErr
	issuer       string
	metadataPath string
	streamIDs    []string
	keys         []jose.JSONWebKey
	queue        []queuedSET
	acked        []string
	pollRequests []PollRequest
	pollErrors   []pollError
	audience     []string
	opts         options
	mu           sync.Mutex
}

// New starts a transmitter and stops it when the test ends.
func New(tb testing.TB, opts ...Option) *Transmitter {
	tb.Helper()

	transmitter := &Transmitter{
		opts: options{
			token:                    DefaultToken,
			audience:                 []string{DefaultAudience},
			streams:                  1,
			deliveryMethodOfStream:   DeliveryMethodPoll,
			deliveryMethodsSupported: []string{DeliveryMethodPoll},
		},
		notify:  make(chan struct{}),
		setErrs: make(map[string]SetErr),
	}

	for _, opt := range opts {
		opt(&transmitter.opts)
	}

	transmitter.audience = transmitter.opts.audience
	for range transmitter.opts.streams {
		transmitter.streamIDs = append(transmitter.streamIDs, rand.Text())
	}

	transmitter.RotateKey(tb)

	prefix := transmitter.opts.issuerPath

	transmitter.metadataPath = WellKnownPath + prefix
	if transmitter.opts.metadataLocation == MetadataAppended {
		transmitter.metadataPath = prefix + WellKnownPath
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET "+transmitter.metadataPath, transmitter.handleMetadata)
	mux.HandleFunc("GET "+prefix+"/ssf/jwks", transmitter.handleJWKS)
	mux.HandleFunc("GET "+prefix+"/ssf/streams", transmitter.handleStreams)
	mux.HandleFunc("POST "+prefix+"/ssf/poll", transmitter.handlePoll)

	transmitter.server = httptest.NewTLSServer(mux)
	tb.Cleanup(transmitter.server.Close)

	transmitter.issuer = transmitter.server.URL + prefix

	return transmitter
}

// Issuer returns the issuer URL, which is also the iss of every SET built by NewSET.
func (t *Transmitter) Issuer() string {
	return t.issuer
}

// MetadataURL returns the URL the configuration metadata is served at.
func (t *Transmitter) MetadataURL() string {
	return t.server.URL + t.metadataPath
}

// ConfigurationEndpoint returns the stream configuration endpoint.
func (t *Transmitter) ConfigurationEndpoint() string {
	return t.issuer + "/ssf/streams"
}

// JWKSURI returns the URL of the JWK Set.
func (t *Transmitter) JWKSURI() string {
	return t.issuer + "/ssf/jwks"
}

// PollEndpoint returns the RFC 8936 poll endpoint of the streams.
func (t *Transmitter) PollEndpoint() string {
	return t.issuer + "/ssf/poll"
}

// Token returns the bearer token the stream and poll endpoints accept.
func (t *Transmitter) Token() string {
	return t.opts.token
}

// Audience returns the aud of the streams.
func (t *Transmitter) Audience() []string {
	return slices.Clone(t.audience)
}

// StreamIDs returns the IDs of the streams the token can read.
func (t *Transmitter) StreamIDs() []string {
	return slices.Clone(t.streamIDs)
}

// Client returns an HTTP client that trusts the transmitter's TLS certificate.
func (t *Transmitter) Client() *http.Client {
	return t.server.Client()
}

// RotateKey publishes a new signing key. Sign uses it from now on; earlier
// keys stay in the JWK Set.
func (t *Transmitter) RotateKey(tb testing.TB) {
	tb.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	require.NoError(tb, err)

	t.mu.Lock()
	defer t.mu.Unlock()

	t.keys = append(t.keys, jose.JSONWebKey{
		Key:       privateKey,
		KeyID:     rand.Text(),
		Algorithm: string(jose.RS256),
		Use:       "sig",
	})
}

// Emit signs set with the current key, queues it for poll delivery and
// returns its jti.
func (t *Transmitter) Emit(tb testing.TB, set SET, opts ...SignOption) string {
	tb.Helper()

	t.EmitToken(set.JTI, t.Sign(tb, set, opts...))

	return set.JTI
}

// EmitSessionRevoked queues a CAEP session-revoked SET for subject and
// returns its jti.
func (t *Transmitter) EmitSessionRevoked(tb testing.TB, subject Subject) string {
	tb.Helper()

	return t.Emit(tb, t.NewSessionRevoked(subject))
}

// EmitToken queues an already encoded SET under jti, for example one that
// Sign built with missing claims or a wrong key. A SET that is still queued
// under the same jti is replaced.
func (t *Transmitter) EmitToken(jti, token string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.queue = slices.DeleteFunc(t.queue, func(set queuedSET) bool { return set.jti == jti })
	t.queue = append(t.queue, queuedSET{jti: jti, token: token})
	t.wakeLocked()
}

// FailNextPoll makes the next poll request fail with status and header,
// for example 429 with a Retry-After header. Calls queue up; each failure
// is used once. A failed request does not process its ack or setErrs.
func (t *Transmitter) FailNextPoll(status int, header http.Header) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.pollErrors = append(t.pollErrors, pollError{status: status, header: header})
	t.wakeLocked()
}

// Pending returns the jti of every SET that is neither acknowledged nor
// reported in setErrs, in delivery order.
func (t *Transmitter) Pending() []string {
	t.mu.Lock()
	defer t.mu.Unlock()

	jtis := make([]string, 0, len(t.queue))
	for _, set := range t.queue {
		jtis = append(jtis, set.jti)
	}

	return jtis
}

// Acked returns the jti of every acknowledged SET in acknowledgement order.
func (t *Transmitter) Acked() []string {
	t.mu.Lock()
	defer t.mu.Unlock()

	return slices.Clone(t.acked)
}

// SetErrs returns the errors receivers reported, by jti.
func (t *Transmitter) SetErrs() map[string]SetErr {
	t.mu.Lock()
	defer t.mu.Unlock()

	return maps.Clone(t.setErrs)
}

// PollRequests returns every poll request with a valid token, including
// injected failures, in arrival order.
func (t *Transmitter) PollRequests() []PollRequest {
	t.mu.Lock()
	defer t.mu.Unlock()

	return slices.Clone(t.pollRequests)
}

// wakeLocked releases long-poll requests waiting for a new SET. t.mu must be held.
func (t *Transmitter) wakeLocked() {
	close(t.notify)
	t.notify = make(chan struct{})
}

func (t *Transmitter) handleMetadata(w http.ResponseWriter, _ *http.Request) {
	metadata := map[string]any{
		"spec_version":               "1_0",
		"issuer":                     t.issuer,
		"delivery_methods_supported": t.opts.deliveryMethodsSupported,
		"authorization_schemes":      []map[string]string{{"spec_urn": "urn:ietf:rfc:6750"}},
	}

	if !t.opts.noJWKSURI {
		metadata["jwks_uri"] = t.JWKSURI()
	}

	if !t.opts.noConfigurationEndpoint {
		metadata["configuration_endpoint"] = t.ConfigurationEndpoint()
	}

	writeJSON(w, metadata)
}

func (t *Transmitter) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	t.mu.Lock()

	keySet := jose.JSONWebKeySet{Keys: make([]jose.JSONWebKey, 0, len(t.keys))}
	for _, key := range t.keys {
		keySet.Keys = append(keySet.Keys, key.Public())
	}

	t.mu.Unlock()

	writeJSON(w, keySet)
}

func (t *Transmitter) handleStreams(w http.ResponseWriter, r *http.Request) {
	if !t.authorized(w, r) {
		return
	}

	streams := make([]map[string]any, 0, len(t.streamIDs))
	for _, streamID := range t.streamIDs {
		streams = append(streams, t.stream(streamID))
	}

	streamID := r.URL.Query().Get("stream_id")
	if streamID == "" {
		writeJSON(w, streams)

		return
	}

	for _, stream := range streams {
		if stream["stream_id"] == streamID {
			writeJSON(w, stream)

			return
		}
	}

	http.Error(w, "stream not found", http.StatusNotFound)
}

func (t *Transmitter) stream(streamID string) map[string]any {
	delivery := map[string]any{"method": t.opts.deliveryMethodOfStream}
	if t.opts.deliveryMethodOfStream == DeliveryMethodPoll {
		delivery["endpoint_url"] = t.PollEndpoint()
	}

	var audience any = t.audience
	if len(t.audience) == 1 {
		audience = t.audience[0]
	}

	return map[string]any{
		"stream_id":        streamID,
		"iss":              t.issuer,
		"aud":              audience,
		"delivery":         delivery,
		"events_supported": []string{EventTypeSessionRevoked, EventTypeCredentialChange},
		"events_requested": []string{EventTypeSessionRevoked},
		"events_delivered": []string{EventTypeSessionRevoked},
		"description":      "ssftest stream",
	}
}

func (t *Transmitter) handlePoll(w http.ResponseWriter, r *http.Request) {
	if !t.authorized(w, r) {
		return
	}

	var request PollRequest

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "invalid poll request: "+err.Error(), http.StatusBadRequest)

		return
	}

	if request.MaxEvents != nil && *request.MaxEvents < 0 {
		http.Error(w, "invalid poll request: maxEvents must not be negative", http.StatusBadRequest)

		return
	}

	t.mu.Lock()
	t.pollRequests = append(t.pollRequests, request)

	if len(t.pollErrors) > 0 {
		failure := t.pollErrors[0]
		t.pollErrors = t.pollErrors[1:]
		t.mu.Unlock()

		maps.Copy(w.Header(), failure.header)
		http.Error(w, http.StatusText(failure.status), failure.status)

		return
	}

	t.settleLocked(request)

	response, wait := t.nextLocked(request)
	t.mu.Unlock()

	if len(response.Sets) == 0 && t.holds(request) {
		if !t.hold(r, wait) {
			return
		}

		t.mu.Lock()
		response, _ = t.nextLocked(request)
		t.mu.Unlock()
	}

	writeJSON(w, response)
}

// holds reports whether a request without events is held (long polling).
// Requests with returnImmediately or maxEvents 0 (ack only) are never held.
func (t *Transmitter) holds(request PollRequest) bool {
	ackOnly := request.MaxEvents != nil && *request.MaxEvents == 0

	return t.opts.longPollHold > 0 && !request.ReturnImmediately && !ackOnly
}

// hold waits until wait is closed or the hold expires. It returns false if
// the request was canceled.
func (t *Transmitter) hold(r *http.Request, wait <-chan struct{}) bool {
	timer := time.NewTimer(t.opts.longPollHold)
	defer timer.Stop()

	select {
	case <-wait:
	case <-timer.C:
	case <-r.Context().Done():
		return false
	}

	return true
}

// settleLocked removes acknowledged and failed SETs from the queue. t.mu must be held.
func (t *Transmitter) settleLocked(request PollRequest) {
	settled := make(map[string]bool)

	for _, jti := range request.Ack {
		if !slices.Contains(t.acked, jti) {
			t.acked = append(t.acked, jti)
		}

		settled[jti] = true
	}

	for jti, setErr := range request.SetErrs {
		t.setErrs[jti] = setErr
		settled[jti] = true
	}

	t.queue = slices.DeleteFunc(t.queue, func(set queuedSET) bool {
		return settled[set.jti]
	})
}

// nextLocked returns the pending SETs for a response and the channel that is
// closed when a new SET arrives. t.mu must be held.
func (t *Transmitter) nextLocked(request PollRequest) (pollResponse, <-chan struct{}) {
	limit := len(t.queue)
	if request.MaxEvents != nil {
		limit = min(limit, *request.MaxEvents)
	}

	response := pollResponse{
		Sets:          make(map[string]string, limit),
		MoreAvailable: len(t.queue) > limit,
	}

	for _, set := range t.queue[:limit] {
		response.Sets[set.jti] = set.token
	}

	return response, t.notify
}

func (t *Transmitter) authorized(w http.ResponseWriter, r *http.Request) bool {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if ok && token == t.opts.token {
		return true
	}

	w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)

	return false
}

func writeJSON(w http.ResponseWriter, body any) {
	payload, err := json.Marshal(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)

		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
}
