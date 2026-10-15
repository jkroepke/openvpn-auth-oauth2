// Package ssf implements the receiver side of the OpenID Shared Signals
// Framework (SSF) 1.0: it verifies Security Event Tokens (SETs, RFC 8417)
// from one trusted transmitter and parses their subject.
//
// The package does not know about OpenVPN, so that it could move to pkg/
// later.
package ssf

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

const (
	// EventTypeSessionRevoked is the CAEP session-revoked event type.
	EventTypeSessionRevoked = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"

	// SETType is the typ header of a SET (RFC 8417, section 2.3).
	SETType = "secevent+jwt"

	// MaxFutureIssuedAt is how far in the future the iat of a SET may be, to
	// tolerate clock skew between the transmitter and the receiver.
	MaxFutureIssuedAt = 5 * time.Minute

	// maxNumericDate is the largest NumericDate a time.Time can represent in
	// nanoseconds since the Unix epoch.
	maxNumericDate = float64(math.MaxInt64 / int64(time.Second))
)

// SignatureAlgorithms returns the JWS algorithms accepted for SETs. Only
// asymmetric algorithms are accepted; none and HMAC are rejected.
func SignatureAlgorithms() []string {
	return []string{
		string(jose.RS256), string(jose.RS384), string(jose.RS512),
		string(jose.PS256), string(jose.PS384), string(jose.PS512),
		string(jose.ES256), string(jose.ES384), string(jose.ES512),
		string(jose.EdDSA),
	}
}

// VerifierConfig configures a Verifier.
type VerifierConfig struct {
	// KeySet verifies SET signatures, usually rp.NewRemoteKeySet for the
	// jwks_uri of the transmitter.
	KeySet oidc.KeySet
	// Issuer is the issuer of the transmitter. The iss claim must equal it.
	Issuer string
	// Audience is the aud of the stream. The aud claim must contain one of them.
	Audience []string
	// CriticalSubjectMembers is critical_subject_members from the transmitter
	// configuration metadata.
	CriticalSubjectMembers []string
	// MaxAge is the maximum age of a SET by its iat. It also bounds how long a
	// processed jti is remembered.
	MaxAge time.Duration
	// AllowEmail accepts email subject identifiers.
	AllowEmail bool
}

// Verifier verifies SETs from one transmitter.
type Verifier struct {
	replay  *replayCache
	now     func() time.Time
	subject subjectParser
	conf    VerifierConfig
}

// Event is a verified SET.
type Event struct {
	// IssuedAt is the iat claim.
	IssuedAt time.Time
	// EventTimestamp is event_timestamp of a CAEP event; zero if absent.
	EventTimestamp time.Time
	// ReasonAdmin is reason_admin of a CAEP event, keyed by language tag.
	ReasonAdmin map[string]string
	// ID is the jti claim.
	ID string
	// Type is the event type URI, the only key of the events claim.
	Type string
	// TransactionID is the txn claim.
	TransactionID string
	// InitiatingEntity is initiating_entity of a CAEP event.
	InitiatingEntity string
	// Subject is the parsed sub_id. It is only set for EventTypeSessionRevoked;
	// other event types are verified but their subject is not parsed.
	Subject Subject
}

// NewVerifier returns a Verifier for conf.
func NewVerifier(conf VerifierConfig) *Verifier {
	return &Verifier{
		conf:    conf,
		now:     time.Now,
		replay:  newReplayCache(),
		subject: subjectParser{allowEmail: conf.AllowEmail, critical: conf.CriticalSubjectMembers},
	}
}

// Verify checks the signature and claims of the SET token and returns the
// event it carries. A returned error is an *Error with the RFC 8935 error code.
//
// Verify does not record the jti. Call Processed once the event has been
// acted on, so a SET that could not be processed is accepted again when the
// transmitter redelivers it.
func (v *Verifier) Verify(ctx context.Context, token string) (Event, error) {
	claims, err := v.verifySignature(ctx, token)
	if err != nil {
		return Event{}, err
	}

	if claims.Issuer != v.conf.Issuer {
		return Event{}, newError(ErrorCodeInvalidIssuer, fmt.Errorf("issuer %q does not match %q", claims.Issuer, v.conf.Issuer))
	}

	if !slices.ContainsFunc(claims.Audience, func(audience string) bool { return slices.Contains(v.conf.Audience, audience) }) {
		return Event{}, newError(ErrorCodeInvalidAudience, fmt.Errorf("audience %q does not contain %q", claims.Audience, v.conf.Audience))
	}

	event, err := v.verifyClaims(claims)
	if err != nil {
		return Event{}, newError(ErrorCodeInvalidRequest, err)
	}

	return event, nil
}

// Processed records the jti of event, so the same SET is rejected with
// ErrReplay until its iat is older than the maximum age.
func (v *Verifier) Processed(event Event) {
	v.replay.add(event.ID, event.IssuedAt.Add(v.conf.MaxAge), v.now())
}

// verifySignature checks the typ header and the signature of token and
// returns its claims.
func (v *Verifier) verifySignature(ctx context.Context, token string) (*setClaims, error) {
	jws, err := jose.ParseSigned(token, joseSignatureAlgorithms())
	if err != nil {
		return nil, newError(ErrorCodeInvalidRequest, fmt.Errorf("parse SET: %w", err))
	}

	if len(jws.Signatures) != 1 {
		return nil, newError(ErrorCodeInvalidRequest, errors.New("token must have exactly one signature"))
	}

	typ, ok := jws.Signatures[0].Protected.ExtraHeaders[jose.HeaderType].(string)
	if !ok || (!strings.EqualFold(typ, SETType) && !strings.EqualFold(typ, "application/"+SETType)) {
		return nil, newError(ErrorCodeInvalidRequest, fmt.Errorf("typ header %q is not %q", typ, SETType))
	}

	claims := &setClaims{}
	payload := jws.UnsafePayloadWithoutVerification()

	if err = oidc.CheckSignature(ctx, token, payload, claims, SignatureAlgorithms(), v.conf.KeySet); err != nil {
		return nil, newError(ErrorCodeInvalidKey, fmt.Errorf("verify signature: %w", err))
	}

	if err = json.Unmarshal(payload, claims); err != nil {
		return nil, newError(ErrorCodeInvalidRequest, fmt.Errorf("decode SET claims: %w", err))
	}

	return claims, nil
}

// verifyClaims checks the claims other than iss and aud and builds the event.
func (v *Verifier) verifyClaims(claims *setClaims) (Event, error) {
	issuedAt, err := v.verifyRegisteredClaims(claims)
	if err != nil {
		return Event{}, err
	}

	if len(claims.Events) != 1 {
		return Event{}, fmt.Errorf("events claim must contain exactly one event, got %d", len(claims.Events))
	}

	event := Event{ID: claims.JTI, TransactionID: claims.TXN, IssuedAt: issuedAt}

	var payload json.RawMessage
	for event.Type, payload = range claims.Events {
		break
	}

	if event.Type != EventTypeSessionRevoked {
		return event, nil
	}

	if err = event.decodeCAEP(payload); err != nil {
		return Event{}, err
	}

	if len(claims.SubjectID) == 0 {
		return Event{}, errors.New("sub_id claim is missing")
	}

	if event.Subject, err = v.subject.parse(claims.SubjectID); err != nil {
		return Event{}, fmt.Errorf("sub_id: %w", err)
	}

	return event, nil
}

// verifyRegisteredClaims checks sub, exp, jti and iat and returns the iat.
func (v *Verifier) verifyRegisteredClaims(claims *setClaims) (time.Time, error) {
	if len(claims.Sub) != 0 {
		return time.Time{}, errors.New("sub claim is not allowed in an SSF event")
	}

	if len(claims.Exp) != 0 {
		return time.Time{}, errors.New("exp claim is not allowed in an SSF event")
	}

	if claims.JTI == "" {
		return time.Time{}, errors.New("jti claim is missing")
	}

	issuedAt, err := v.verifyIssuedAt(claims.IssuedAt)
	if err != nil {
		return time.Time{}, err
	}

	if v.replay.seen(claims.JTI, v.now()) {
		return time.Time{}, fmt.Errorf("jti %q: %w", claims.JTI, ErrReplay)
	}

	return issuedAt, nil
}

// verifyIssuedAt checks that iat is present, not older than the maximum age
// and not too far in the future.
func (v *Verifier) verifyIssuedAt(iat *float64) (time.Time, error) {
	if iat == nil {
		return time.Time{}, errors.New("iat claim is missing")
	}

	issuedAt, err := numericDate(*iat)
	if err != nil {
		return time.Time{}, fmt.Errorf("iat: %w", err)
	}

	now := v.now()

	if issuedAt.Before(now.Add(-v.conf.MaxAge)) {
		return time.Time{}, fmt.Errorf("iat %s is more than %s ago", issuedAt.UTC().Format(time.RFC3339), v.conf.MaxAge)
	}

	if issuedAt.After(now.Add(MaxFutureIssuedAt)) {
		return time.Time{}, fmt.Errorf("iat %s is more than %s in the future; check the clocks", issuedAt.UTC().Format(time.RFC3339), MaxFutureIssuedAt)
	}

	return issuedAt, nil
}

// decodeCAEP decodes the CAEP event members the receiver logs.
func (e *Event) decodeCAEP(payload json.RawMessage) error {
	var members caepEvent

	if err := json.Unmarshal(payload, &members); err != nil {
		return fmt.Errorf("decode %s event: %w", e.Type, err)
	}

	if members.EventTimestamp != nil {
		eventTimestamp, err := numericDate(*members.EventTimestamp)
		if err != nil {
			return fmt.Errorf("event_timestamp: %w", err)
		}

		e.EventTimestamp = eventTimestamp
	}

	e.InitiatingEntity = members.InitiatingEntity
	e.ReasonAdmin = members.ReasonAdmin

	return nil
}

// numericDate converts a JWT NumericDate to a time.
func numericDate(value float64) (time.Time, error) {
	if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value > maxNumericDate {
		return time.Time{}, fmt.Errorf("invalid NumericDate %v", value)
	}

	seconds, fraction := math.Modf(value)

	return time.Unix(int64(seconds), int64(fraction*float64(time.Second))), nil
}

func joseSignatureAlgorithms() []jose.SignatureAlgorithm {
	algorithms := SignatureAlgorithms()
	joseAlgorithms := make([]jose.SignatureAlgorithm, 0, len(algorithms))

	for _, algorithm := range algorithms {
		joseAlgorithms = append(joseAlgorithms, jose.SignatureAlgorithm(algorithm))
	}

	return joseAlgorithms
}

// setClaims are the claims of a SET as SSF 1.0 profiles them.
//
//nolint:tagliatelle // RFC 8417 and SSF 1.0 claim names.
type setClaims struct {
	Events    map[string]json.RawMessage `json:"events"`
	IssuedAt  *float64                   `json:"iat"`
	Issuer    string                     `json:"iss"`
	JTI       string                     `json:"jti"`
	TXN       string                     `json:"txn"`
	SubjectID json.RawMessage            `json:"sub_id"`
	Sub       json.RawMessage            `json:"sub"`
	Exp       json.RawMessage            `json:"exp"`
	Audience  audience                   `json:"aud"`
}

// SetSignatureAlgorithm implements oidc.ClaimsSignature.
func (*setClaims) SetSignatureAlgorithm(jose.SignatureAlgorithm) {}

// caepEvent holds the CAEP event members the receiver logs.
//
//nolint:tagliatelle // CAEP member names.
type caepEvent struct {
	EventTimestamp   *float64          `json:"event_timestamp"`
	ReasonAdmin      map[string]string `json:"reason_admin"`
	InitiatingEntity string            `json:"initiating_entity"`
}

// audience is the aud claim, a string or an array of strings.
type audience []string

// UnmarshalJSON implements json.Unmarshaler.
func (a *audience) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = audience{single}

		return nil
	}

	var multiple []string
	if err := json.Unmarshal(data, &multiple); err != nil {
		return errors.New("aud is neither a string nor an array of strings")
	}

	*a = multiple

	return nil
}
