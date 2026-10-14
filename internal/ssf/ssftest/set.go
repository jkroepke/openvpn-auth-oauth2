package ssftest

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
)

// SET holds the claims of a Security Event Token as SSF 1.0 profiles them
// (RFC 8417): the subject is a top-level sub_id, and exp and sub are not used.
//
//nolint:tagliatelle // RFC 8417 and SSF 1.0 claim names.
type SET struct {
	Events    map[string]any `json:"events"`
	SubjectID Subject        `json:"sub_id,omitempty"`
	Issuer    string         `json:"iss"`
	JTI       string         `json:"jti"`
	TXN       string         `json:"txn,omitempty"`
	Audience  Audience       `json:"aud,omitempty"`
	IssuedAt  int64          `json:"iat"`
}

// Audience is the aud claim. A single audience is encoded as a string, more
// than one as an array.
type Audience []string

// MarshalJSON implements json.Marshaler.
func (a Audience) MarshalJSON() ([]byte, error) {
	if len(a) == 1 {
		return json.Marshal(a[0]) //nolint:wrapcheck
	}

	return json.Marshal([]string(a)) //nolint:wrapcheck
}

// UnmarshalJSON implements json.Unmarshaler and accepts a string or an array.
func (a *Audience) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = Audience{single}

		return nil
	}

	return json.Unmarshal(data, (*[]string)(a)) //nolint:wrapcheck
}

// Subject is a subject identifier (RFC 9493) as used in sub_id.
type Subject map[string]any

const subjectFormat = "format"

// IssSub returns an iss_sub subject identifier.
func IssSub(iss, sub string) Subject {
	return Subject{subjectFormat: "iss_sub", "iss": iss, "sub": sub}
}

// Email returns an email subject identifier.
func Email(email string) Subject {
	return Subject{subjectFormat: "email", "email": email}
}

// Opaque returns an opaque subject identifier.
func Opaque(id string) Subject {
	return Subject{subjectFormat: "opaque", "id": id}
}

// Complex returns a complex subject identifier with the given members,
// for example "user" and "session".
func Complex(members map[string]Subject) Subject {
	subject := Subject{subjectFormat: "complex"}
	for name, member := range members {
		subject[name] = member
	}

	return subject
}

// UserSession returns a complex subject identifier with a user and a session member.
func UserSession(user, session Subject) Subject {
	return Complex(map[string]Subject{"user": user, "session": session})
}

// NewSET returns a SET from this transmitter with a fresh jti and txn, the
// stream audience, the current time as iat and one event of eventType.
// A nil event is sent as an empty object.
func (t *Transmitter) NewSET(subject Subject, eventType string, event map[string]any) SET {
	if event == nil {
		event = make(map[string]any)
	}

	return SET{
		Issuer:    t.issuer,
		JTI:       rand.Text(),
		TXN:       rand.Text(),
		Audience:  Audience(t.audience),
		IssuedAt:  time.Now().Unix(),
		SubjectID: subject,
		Events:    map[string]any{eventType: event},
	}
}

// NewSessionRevoked returns a CAEP session-revoked SET for subject.
func (t *Transmitter) NewSessionRevoked(subject Subject) SET {
	return t.NewSET(subject, EventTypeSessionRevoked, map[string]any{
		"event_timestamp":   time.Now().Unix(),
		"initiating_entity": "admin",
	})
}

// SignOption changes how Sign builds the JWS.
type SignOption func(*signOptions)

type signOptions struct {
	key     *jose.SigningKey
	keyID   *string
	typ     string
	omitTyp bool
}

// WithType sets the typ header. An empty value omits it.
func WithType(typ string) SignOption {
	return func(o *signOptions) {
		o.typ = typ
		o.omitTyp = typ == ""
	}
}

// WithKeyID sets the kid header instead of the kid of the current key.
// An empty value omits it.
func WithKeyID(keyID string) SignOption {
	return func(o *signOptions) {
		o.keyID = &keyID
	}
}

// WithSigningKey signs with key instead of the current published key.
// The key is not added to the JWK Set.
func WithSigningKey(key jose.SigningKey) SignOption {
	return func(o *signOptions) {
		o.key = &key
	}
}

// WithUnpublishedKey signs with a fresh RSA key that is not in the JWK Set,
// using the kid of the current published key.
func WithUnpublishedKey(tb testing.TB) SignOption {
	tb.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	require.NoError(tb, err)

	return func(o *signOptions) {
		o.key = &jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}
	}
}

// Sign returns claims as a compact JWS signed with the current published key.
// claims is usually a SET, but any JSON-encodable value is accepted so tests
// can add or remove claims.
func (t *Transmitter) Sign(tb testing.TB, claims any, opts ...SignOption) string {
	tb.Helper()

	options := signOptions{typ: SETType}
	for _, opt := range opts {
		opt(&options)
	}

	t.mu.Lock()
	current := t.keys[len(t.keys)-1]
	t.mu.Unlock()

	keyID := current.KeyID
	signingKey := jose.SigningKey{Algorithm: jose.RS256, Key: current.Key}

	if options.key != nil {
		signingKey = *options.key
	}

	if options.keyID != nil {
		keyID = *options.keyID
	}

	signerOptions := &jose.SignerOptions{}
	if !options.omitTyp {
		signerOptions = signerOptions.WithType(jose.ContentType(options.typ))
	}

	if keyID != "" {
		signerOptions = signerOptions.WithHeader(jose.HeaderKey("kid"), keyID)
	}

	signer, err := jose.NewSigner(signingKey, signerOptions)
	require.NoError(tb, err)

	payload, err := json.Marshal(claims)
	require.NoError(tb, err)

	jws, err := signer.Sign(payload)
	require.NoError(tb, err)

	token, err := jws.CompactSerialize()
	require.NoError(tb, err)

	return token
}
