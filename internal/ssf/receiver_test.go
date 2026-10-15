package ssf_test

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/ssf"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/ssf/ssftest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testInterval = 10 * time.Millisecond
	waitFor      = 5 * time.Second
	tick         = 5 * time.Millisecond
)

// handler records handled events. It fails while failures is positive.
type handler struct {
	err      error
	events   []ssf.Event
	failures int
	revoked  int
	mu       sync.Mutex
}

func (h *handler) HandleEvent(_ context.Context, event ssf.Event) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.events = append(h.events, event)

	if h.failures > 0 {
		h.failures--

		return 0, h.err
	}

	return h.revoked, nil
}

func (h *handler) handled() []ssf.Event {
	h.mu.Lock()
	defer h.mu.Unlock()

	return slices.Clone(h.events)
}

// receiverMetrics records receiver metrics.
type receiverMetrics struct {
	outcomes   map[string]int
	pollErrors int
	polls      int
	mu         sync.Mutex
}

func (m *receiverMetrics) SSFEvent(outcome string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.outcomes[outcome]++
}

func (m *receiverMetrics) SSFPollError() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.pollErrors++
}

func (m *receiverMetrics) SSFPollSucceeded(time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.polls++
}

func (m *receiverMetrics) outcome(outcome string) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.outcomes[outcome]
}

func (m *receiverMetrics) errors() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.pollErrors
}

type receiverSuite struct {
	transmitter *ssftest.Transmitter
	handler     *handler
	metrics     *receiverMetrics
	verifier    *ssf.Verifier
	done        chan error
}

// startReceiver runs a receiver against transmitter until the test ends.
func startReceiver(t *testing.T, transmitter *ssftest.Transmitter, eventHandler *handler, maxEvents int) *receiverSuite {
	t.Helper()

	suite := &receiverSuite{
		transmitter: transmitter,
		handler:     eventHandler,
		metrics:     &receiverMetrics{outcomes: make(map[string]int)},
		verifier:    newVerifier(t, transmitter),
		done:        make(chan error, 1),
	}

	receiver := ssf.NewReceiver(slog.New(slog.DiscardHandler), ssf.ReceiverConfig{
		Client:    transmitter.Client(),
		Verifier:  suite.verifier,
		Handler:   eventHandler,
		Metrics:   suite.metrics,
		Endpoint:  transmitter.PollEndpoint(),
		Token:     transmitter.Token(),
		Interval:  testInterval,
		MaxEvents: maxEvents,
	})

	ctx, cancel := context.WithCancel(t.Context())

	go func() { suite.done <- receiver.Run(ctx) }()

	t.Cleanup(func() {
		cancel()

		select {
		case err := <-suite.done:
			require.NoError(t, err)
		case <-time.After(waitFor):
			t.Error("receiver did not stop")
		}
	})

	return suite
}

func (s *receiverSuite) waitAcked(t *testing.T, jtis ...string) {
	t.Helper()

	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		for _, jti := range jtis {
			assert.Contains(collect, s.transmitter.Acked(), jti)
		}
	}, waitFor, tick)
}

func revokedSubject() ssftest.Subject {
	return ssftest.UserSession(ssftest.IssSub("https://idp.example.com", "user-1"), ssftest.Opaque("sid-1"))
}

func TestReceiverHandlesAndAcknowledges(t *testing.T) {
	t.Parallel()

	transmitter := ssftest.New(t)
	suite := startReceiver(t, transmitter, &handler{revoked: 1}, 100)

	jti := transmitter.EmitSessionRevoked(t, revokedSubject())
	suite.waitAcked(t, jti)

	events := suite.handler.handled()
	require.Len(t, events, 1)
	assert.Equal(t, jti, events[0].ID)
	assert.Equal(t, ssf.Subject{Issuer: "https://idp.example.com", Subject: "user-1", SessionID: "sid-1"}, events[0].Subject)
	assert.Equal(t, 1, suite.metrics.outcome(ssf.OutcomeRevoked))
	assert.Empty(t, transmitter.SetErrs())
}

func TestReceiverNoMatch(t *testing.T) {
	t.Parallel()

	transmitter := ssftest.New(t)
	suite := startReceiver(t, transmitter, &handler{}, 100)

	suite.waitAcked(t, transmitter.EmitSessionRevoked(t, revokedSubject()))
	assert.Equal(t, 1, suite.metrics.outcome(ssf.OutcomeNoMatch))
}

func TestReceiverMoreAvailable(t *testing.T) {
	t.Parallel()

	transmitter := ssftest.New(t)

	jtis := make([]string, 0, 5)
	for range 5 {
		jtis = append(jtis, transmitter.EmitSessionRevoked(t, revokedSubject()))
	}

	suite := startReceiver(t, transmitter, &handler{revoked: 1}, 2)
	suite.waitAcked(t, jtis...)

	assert.Len(t, suite.handler.handled(), 5)
	assert.Empty(t, transmitter.Pending())

	for _, request := range transmitter.PollRequests() {
		require.NotNil(t, request.MaxEvents)
		assert.Equal(t, 2, *request.MaxEvents)
		assert.False(t, request.ReturnImmediately, "long polling is requested")
	}
}

func TestReceiverRejectsInvalidSET(t *testing.T) {
	t.Parallel()

	transmitter := ssftest.New(t)
	suite := startReceiver(t, transmitter, &handler{}, 100)

	set := transmitter.NewSessionRevoked(revokedSubject())
	set.Issuer = "https://other.example.com"
	transmitter.EmitToken(set.JTI, transmitter.Sign(t, set))

	unsigned := transmitter.NewSessionRevoked(revokedSubject())
	transmitter.EmitToken(unsigned.JTI, transmitter.Sign(t, unsigned, ssftest.WithUnpublishedKey(t)))

	mismatch := transmitter.NewSessionRevoked(revokedSubject())
	transmitter.EmitToken("other-jti", transmitter.Sign(t, mismatch))

	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		assert.Len(collect, transmitter.SetErrs(), 3)
	}, waitFor, tick)

	setErrs := transmitter.SetErrs()
	assert.Equal(t, ssf.ErrorCodeInvalidIssuer, setErrs[set.JTI].Err)
	assert.Equal(t, ssf.ErrorCodeInvalidKey, setErrs[unsigned.JTI].Err)
	assert.Equal(t, ssf.ErrorCodeInvalidRequest, setErrs["other-jti"].Err)
	assert.NotEmpty(t, setErrs[set.JTI].Description)
	assert.Empty(t, suite.handler.handled())
	assert.Equal(t, 3, suite.metrics.outcome(ssf.OutcomeInvalid))
	assert.Empty(t, transmitter.Pending())
}

func TestReceiverIgnoresUnsupportedEvents(t *testing.T) {
	t.Parallel()

	transmitter := ssftest.New(t)
	suite := startReceiver(t, transmitter, &handler{}, 100)

	other := transmitter.Emit(t, transmitter.NewSET(ssftest.Opaque("x"), ssftest.EventTypeCredentialChange, nil))
	unsupported := transmitter.EmitSessionRevoked(t, ssftest.Opaque("x"))

	suite.waitAcked(t, other, unsupported)
	assert.Empty(t, suite.handler.handled())
	assert.Equal(t, 2, suite.metrics.outcome(ssf.OutcomeIgnored))
	assert.Empty(t, transmitter.SetErrs())
}

func TestReceiverRetriesFailedHandler(t *testing.T) {
	t.Parallel()

	transmitter := ssftest.New(t)
	suite := startReceiver(t, transmitter, &handler{failures: 2, err: errors.New("management interface down"), revoked: 1}, 100)

	jti := transmitter.EmitSessionRevoked(t, revokedSubject())
	suite.waitAcked(t, jti)

	events := suite.handler.handled()
	require.Len(t, events, 3, "the event is delivered again until the handler succeeds")
	assert.Equal(t, jti, events[2].ID)
	assert.Equal(t, 2, suite.metrics.outcome(ssf.OutcomeError))
	assert.Equal(t, 1, suite.metrics.outcome(ssf.OutcomeRevoked))
}

func TestReceiverAcknowledgesReplay(t *testing.T) {
	t.Parallel()

	transmitter := ssftest.New(t)
	suite := startReceiver(t, transmitter, &handler{revoked: 1}, 100)

	set := transmitter.NewSessionRevoked(revokedSubject())
	token := transmitter.Sign(t, set)

	transmitter.EmitToken(set.JTI, token)
	suite.waitAcked(t, set.JTI)

	// The transmitter delivers the same SET again, for example after losing
	// the acknowledgement.
	transmitter.EmitToken(set.JTI, token)

	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		assert.Equal(collect, 1, suite.metrics.outcome(ssf.OutcomeReplay))
		assert.Empty(collect, transmitter.Pending())
	}, waitFor, tick)

	assert.Len(t, suite.handler.handled(), 1)
}

func TestReceiverRecoversFromPollErrors(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		header http.Header
		name   string
		status int
	}{
		{name: "server error", status: http.StatusInternalServerError},
		{name: "unauthorized", status: http.StatusUnauthorized},
		{name: "rate limited", status: http.StatusTooManyRequests, header: http.Header{"Retry-After": {"0"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			transmitter := ssftest.New(t)
			transmitter.FailNextPoll(tc.status, tc.header)
			transmitter.FailNextPoll(tc.status, tc.header)

			jti := transmitter.EmitSessionRevoked(t, revokedSubject())
			suite := startReceiver(t, transmitter, &handler{revoked: 1}, 100)

			suite.waitAcked(t, jti)
			assert.Equal(t, 2, suite.metrics.errors())
		})
	}
}

func TestReceiverLongPoll(t *testing.T) {
	t.Parallel()

	transmitter := ssftest.New(t, ssftest.WithLongPollHold(time.Minute))
	suite := startReceiver(t, transmitter, &handler{revoked: 1}, 100)

	// Wait until the receiver is held by the transmitter, then emit.
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		assert.NotEmpty(collect, transmitter.PollRequests())
	}, waitFor, tick)

	suite.waitAcked(t, transmitter.EmitSessionRevoked(t, revokedSubject()))
}

func TestReceiverStopsWhenCanceled(t *testing.T) {
	t.Parallel()

	transmitter := ssftest.New(t, ssftest.WithLongPollHold(time.Minute))
	verifier := newVerifier(t, transmitter)
	receiver := ssf.NewReceiver(slog.New(slog.DiscardHandler), ssf.ReceiverConfig{
		Client:    transmitter.Client(),
		Verifier:  verifier,
		Handler:   &handler{},
		Endpoint:  transmitter.PollEndpoint(),
		Token:     transmitter.Token(),
		Interval:  time.Hour,
		MaxEvents: 1,
	})

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)

	go func() { done <- receiver.Run(ctx) }()

	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		assert.NotEmpty(collect, transmitter.PollRequests())
	}, waitFor, tick)

	cancel()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(waitFor):
		t.Fatal("receiver did not stop while a long poll was held")
	}
}
