package ssf

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"slices"
	"time"
)

// Outcomes of a received SET, as reported to Metrics.SSFEvent.
const (
	OutcomeRevoked = "revoked"
	OutcomeNoMatch = "no_match"
	OutcomeIgnored = "ignored"
	OutcomeInvalid = "invalid"
	OutcomeReplay  = "replay"
	OutcomeError   = "error"
)

const (
	// MaxBackoff is the longest wait between polls after transport errors.
	MaxBackoff = 5 * time.Minute
	// MaxRetryAfter caps the Retry-After delay a transmitter can ask for.
	MaxRetryAfter = time.Hour
	// PollTimeout bounds one poll request, including a long-poll hold.
	PollTimeout = 2 * time.Minute
)

// Handler acts on a verified session-revoked event. It returns the number of
// sessions it revoked. An error means the event was not fully applied; it is
// not acknowledged, so the transmitter delivers it again.
type Handler interface {
	HandleEvent(ctx context.Context, event Event) (int, error)
}

// Metrics records receiver metrics. *metrics.Metrics implements it.
type Metrics interface {
	SSFEvent(outcome string)
	SSFPollError()
	SSFPollSucceeded(at time.Time)
}

// ReceiverConfig configures a Receiver.
type ReceiverConfig struct {
	Client   *http.Client
	Verifier *Verifier
	Handler  Handler
	Metrics  Metrics
	// Endpoint is the poll endpoint, delivery.endpoint_url of the stream.
	Endpoint string
	// Token is the bearer token for the poll endpoint.
	Token string
	// Interval is the minimum time between two polls that return no events,
	// and the first backoff delay after an error.
	Interval time.Duration
	// MaxEvents is maxEvents in the poll request.
	MaxEvents int
}

// Receiver polls one stream (RFC 8936), verifies each SET and hands
// session-revoked events to the Handler. A SET is acknowledged only after it
// was handled, rejected with setErrs if it failed verification, and left
// unacknowledged if the handler failed, so the transmitter delivers it again.
type Receiver struct {
	logger  *slog.Logger
	setErrs map[string]SetErr
	ack     []string
	conf    ReceiverConfig
}

// NewReceiver returns a Receiver for conf. The HTTP client is copied without
// its overall timeout, since a long-poll request is held by the transmitter;
// each request is bounded by PollTimeout instead.
func NewReceiver(logger *slog.Logger, conf ReceiverConfig) *Receiver {
	client := *conf.Client
	client.Timeout = 0
	conf.Client = &client

	if conf.Metrics == nil {
		conf.Metrics = noopMetrics{}
	}

	return &Receiver{
		logger:  logger,
		conf:    conf,
		setErrs: make(map[string]SetErr),
	}
}

// Run polls until ctx is canceled. Transport errors are logged and retried
// with backoff; Run only returns when ctx is done.
func (r *Receiver) Run(ctx context.Context) error {
	r.logger.LogAttrs(ctx, slog.LevelInfo, "SSF receiver started", slog.String("endpoint", r.conf.Endpoint))

	var failures int

	for {
		started := time.Now()

		response, err := r.poll(ctx)
		if ctx.Err() != nil {
			return nil //nolint:nilerr // a poll error after cancellation is the cancellation itself
		}

		var wait time.Duration

		if err != nil {
			failures++
			wait = r.backoff(ctx, err, failures)
		} else {
			failures = 0

			if retry := r.process(ctx, response.Sets); retry || !r.pollAgain(response) {
				wait = r.conf.Interval - time.Since(started)
			}
		}

		if !sleep(ctx, wait) {
			return nil
		}
	}
}

// pollAgain reports whether the next poll should follow at once: more events
// are waiting, or acknowledgements are pending.
func (r *Receiver) pollAgain(response pollResponse) bool {
	return response.MoreAvailable || len(r.ack) > 0 || len(r.setErrs) > 0
}

// poll sends the pending acknowledgements and errors and returns the next
// batch. They are cleared only once the transmitter has received them.
func (r *Receiver) poll(ctx context.Context) (pollResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, PollTimeout)
	defer cancel()

	response, err := poll(ctx, r.conf.Client, r.conf.Endpoint, r.conf.Token, pollRequest{
		Ack:       r.ack,
		SetErrs:   r.setErrs,
		MaxEvents: r.conf.MaxEvents,
	})
	if err != nil {
		return pollResponse{}, err
	}

	r.ack = nil
	r.setErrs = make(map[string]SetErr)
	r.conf.Metrics.SSFPollSucceeded(time.Now())

	return response, nil
}

// backoff logs a poll error and returns how long to wait before the next poll.
func (r *Receiver) backoff(ctx context.Context, err error, failures int) time.Duration {
	r.conf.Metrics.SSFPollError()

	wait := min(r.conf.Interval<<min(failures-1, 16), MaxBackoff)

	level := slog.LevelWarn
	message := "SSF poll failed"

	if statusErr, ok := errors.AsType[*StatusError](err); ok {
		if statusErr.RetryAfter > 0 {
			wait = min(statusErr.RetryAfter, MaxRetryAfter)
		}

		if statusErr.StatusCode == http.StatusUnauthorized || statusErr.StatusCode == http.StatusForbidden {
			level = slog.LevelError
			message = "SSF poll was rejected; check ssf.poll.token"
		}
	}

	r.logger.LogAttrs(ctx, level, message,
		slog.Any("err", err),
		slog.Int("failures", failures),
		slog.Duration("retry_in", wait),
	)

	return wait
}

// process verifies and handles a batch of SETs. It reports whether a handler
// failed, in which case the next poll waits for the interval.
func (r *Receiver) process(ctx context.Context, sets map[string]string) bool {
	var failed bool

	for _, jti := range slices.Sorted(maps.Keys(sets)) {
		if ctx.Err() != nil {
			return true
		}

		if !r.processSET(ctx, jti, sets[jti]) {
			failed = true
		}
	}

	return failed
}

// processSET handles one SET and records how to settle it. It returns false
// if the SET has to be delivered again.
func (r *Receiver) processSET(ctx context.Context, jti, token string) bool {
	logger := r.logger.With(slog.String("jti", jti))

	event, err := r.conf.Verifier.Verify(ctx, token)
	if err == nil && event.ID != jti {
		err = newError(ErrorCodeInvalidRequest, fmt.Errorf("jti claim %q does not match the poll response key", event.ID))
	}

	if ctx.Err() != nil {
		return false
	}

	switch {
	case errors.Is(err, ErrReplay):
		logger.LogAttrs(ctx, slog.LevelDebug, "SSF event was already processed")
		r.settle(jti, OutcomeReplay)
	case errors.Is(err, ErrUnsupportedSubject):
		logger.LogAttrs(ctx, slog.LevelInfo, "ignoring SSF event with an unsupported subject", slog.Any("err", err))
		r.settle(jti, OutcomeIgnored)
	case err != nil:
		r.reject(ctx, logger, jti, err)
	case event.Type != EventTypeSessionRevoked:
		logger.LogAttrs(ctx, slog.LevelInfo, "ignoring unsupported SSF event type", slog.String("type", event.Type))
		r.settle(jti, OutcomeIgnored)
	default:
		return r.handle(ctx, logger, event)
	}

	return true
}

// reject records a SET that failed verification in setErrs.
func (r *Receiver) reject(ctx context.Context, logger *slog.Logger, jti string, err error) {
	setErr := SetErr{Err: ErrorCodeInvalidRequest, Description: err.Error()}

	if verifyErr, ok := errors.AsType[*Error](err); ok {
		setErr = SetErr{Err: verifyErr.Code, Description: verifyErr.Description()}
	}

	logger.LogAttrs(ctx, slog.LevelWarn, "rejecting SSF event",
		slog.String("code", setErr.Err),
		slog.Any("err", err),
	)

	r.setErrs[jti] = setErr
	r.conf.Metrics.SSFEvent(OutcomeInvalid)
}

// handle applies a session-revoked event and acknowledges it on success.
func (r *Receiver) handle(ctx context.Context, logger *slog.Logger, event Event) bool {
	logger = logger.With(
		slog.String("txn", event.TransactionID),
		slog.String("subject_iss", event.Subject.Issuer),
		slog.String("subject_sub", event.Subject.Subject),
		slog.String("subject_sid", event.Subject.SessionID),
		slog.String("subject_email", event.Subject.Email),
		slog.String("initiating_entity", event.InitiatingEntity),
		slog.Any("reason_admin", event.ReasonAdmin),
	)

	revoked, err := r.conf.Handler.HandleEvent(ctx, event)
	if err != nil {
		logger.LogAttrs(ctx, slog.LevelWarn, "unable to apply SSF session-revoked event; it will be retried", slog.Any("err", err))
		r.conf.Metrics.SSFEvent(OutcomeError)

		return false
	}

	r.conf.Verifier.Processed(event)

	outcome := OutcomeRevoked
	if revoked == 0 {
		outcome = OutcomeNoMatch
	}

	logger.LogAttrs(ctx, slog.LevelInfo, "applied SSF session-revoked event", slog.Int("revoked", revoked))
	r.settle(event.ID, outcome)

	return true
}

// settle acknowledges jti in the next poll request.
func (r *Receiver) settle(jti, outcome string) {
	r.ack = append(r.ack, jti)
	r.conf.Metrics.SSFEvent(outcome)
}

// sleep waits for d or until ctx is done, and reports whether ctx is still active.
func sleep(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}

	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

type noopMetrics struct{}

func (noopMetrics) SSFEvent(string)            {}
func (noopMetrics) SSFPollError()              {}
func (noopMetrics) SSFPollSucceeded(time.Time) {}
