package ssf_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/ssf"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/ssf/ssftest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
)

const eventTypeCredentialChange = "https://schemas.openid.net/secevent/caep/event-type/credential-change"

func newVerifier(t *testing.T, transmitter *ssftest.Transmitter, modify ...func(*ssf.VerifierConfig)) *ssf.Verifier {
	t.Helper()

	conf := ssf.VerifierConfig{
		KeySet:   rp.NewRemoteKeySet(transmitter.Client(), transmitter.JWKSURI()),
		Issuer:   transmitter.Issuer(),
		Audience: transmitter.Audience(),
		MaxAge:   time.Hour,
	}

	for _, fn := range modify {
		fn(&conf)
	}

	return ssf.NewVerifier(conf)
}

// claims returns set as a claims map that a test can change.
func claims(t *testing.T, set ssftest.SET) map[string]any {
	t.Helper()

	data, err := json.Marshal(set)
	require.NoError(t, err)

	var result map[string]any

	require.NoError(t, json.Unmarshal(data, &result))

	return result
}

func TestVerify(t *testing.T) {
	t.Parallel()

	transmitter := ssftest.New(t)
	issuer := transmitter.Issuer()
	user := ssftest.IssSub("https://idp.example.com", "user-1")
	session := ssftest.Opaque("sid-1")
	revoked := func() ssftest.SET { return transmitter.NewSessionRevoked(user) }

	for _, tc := range []struct {
		token   func(t *testing.T) string
		modify  func(*ssf.VerifierConfig)
		subject ssf.Subject
		name    string
		code    string
		err     error
	}{
		{
			name: "iss_sub",
			token: func(t *testing.T) string {
				t.Helper()

				return transmitter.Sign(t, revoked())
			},
			subject: ssf.Subject{Issuer: "https://idp.example.com", Subject: "user-1"},
		},
		{
			name: "complex with user and session",
			token: func(t *testing.T) string {
				t.Helper()

				return transmitter.Sign(t, transmitter.NewSessionRevoked(ssftest.UserSession(user, session)))
			},
			subject: ssf.Subject{Issuer: "https://idp.example.com", Subject: "user-1", SessionID: "sid-1"},
		},
		{
			name: "complex with session only",
			token: func(t *testing.T) string {
				t.Helper()

				return transmitter.Sign(t, transmitter.NewSessionRevoked(ssftest.Complex(map[string]ssftest.Subject{"session": session})))
			},
			subject: ssf.Subject{SessionID: "sid-1"},
		},
		{
			name: "complex with user only and an ignored member",
			token: func(t *testing.T) string {
				t.Helper()

				return transmitter.Sign(t, transmitter.NewSessionRevoked(ssftest.Complex(map[string]ssftest.Subject{
					"user":   user,
					"tenant": ssftest.Opaque("tenant-1"),
				})))
			},
			subject: ssf.Subject{Issuer: "https://idp.example.com", Subject: "user-1"},
		},
		{
			name: "complex with a critical member",
			token: func(t *testing.T) string {
				t.Helper()

				return transmitter.Sign(t, transmitter.NewSessionRevoked(ssftest.Complex(map[string]ssftest.Subject{
					"user":   user,
					"tenant": ssftest.Opaque("tenant-1"),
				})))
			},
			modify: func(conf *ssf.VerifierConfig) { conf.CriticalSubjectMembers = []string{"tenant"} },
			code:   ssf.ErrorCodeInvalidRequest,
			err:    ssf.ErrUnsupportedSubject,
		},
		{
			name: "complex with a session that is not opaque",
			token: func(t *testing.T) string {
				t.Helper()

				return transmitter.Sign(t, transmitter.NewSessionRevoked(ssftest.Complex(map[string]ssftest.Subject{"session": user})))
			},
			code: ssf.ErrorCodeInvalidRequest,
			err:  ssf.ErrUnsupportedSubject,
		},
		{
			name: "complex without user or session",
			token: func(t *testing.T) string {
				t.Helper()

				return transmitter.Sign(t, transmitter.NewSessionRevoked(ssftest.Complex(map[string]ssftest.Subject{"device": ssftest.Opaque("d")})))
			},
			code: ssf.ErrorCodeInvalidRequest,
			err:  ssf.ErrUnsupportedSubject,
		},
		{
			name: "email",
			token: func(t *testing.T) string {
				t.Helper()

				return transmitter.Sign(t, transmitter.NewSessionRevoked(ssftest.Email("alice@example.com")))
			},
			modify:  func(conf *ssf.VerifierConfig) { conf.AllowEmail = true },
			subject: ssf.Subject{Email: "alice@example.com"},
		},
		{
			name: "email disabled",
			token: func(t *testing.T) string {
				t.Helper()

				return transmitter.Sign(t, transmitter.NewSessionRevoked(ssftest.Email("alice@example.com")))
			},
			code: ssf.ErrorCodeInvalidRequest,
			err:  ssf.ErrUnsupportedSubject,
		},
		{
			name: "email disabled in a complex user member",
			token: func(t *testing.T) string {
				t.Helper()

				return transmitter.Sign(t, transmitter.NewSessionRevoked(ssftest.UserSession(ssftest.Email("alice@example.com"), session)))
			},
			code: ssf.ErrorCodeInvalidRequest,
			err:  ssf.ErrUnsupportedSubject,
		},
		{
			name: "opaque subject",
			token: func(t *testing.T) string {
				t.Helper()

				return transmitter.Sign(t, transmitter.NewSessionRevoked(ssftest.Opaque("x")))
			},
			code: ssf.ErrorCodeInvalidRequest,
			err:  ssf.ErrUnsupportedSubject,
		},
		{
			name: "iss_sub without sub",
			token: func(t *testing.T) string {
				t.Helper()

				return transmitter.Sign(t, transmitter.NewSessionRevoked(ssftest.Subject{"format": "iss_sub", "iss": "https://idp.example.com"}))
			},
			code: ssf.ErrorCodeInvalidRequest,
		},
		{
			name: "subject member is not a string",
			token: func(t *testing.T) string {
				t.Helper()

				return transmitter.Sign(t, transmitter.NewSessionRevoked(ssftest.Subject{"format": "iss_sub", "iss": 1, "sub": "x"}))
			},
			code: ssf.ErrorCodeInvalidRequest,
		},
		{
			name: "subject without format",
			token: func(t *testing.T) string {
				t.Helper()

				return transmitter.Sign(t, transmitter.NewSessionRevoked(ssftest.Subject{"sub": "x"}))
			},
			code: ssf.ErrorCodeInvalidRequest,
		},
		{
			name: "subject is not an object",
			token: func(t *testing.T) string {
				t.Helper()

				set := claims(t, revoked())
				set["sub_id"] = "user-1"

				return transmitter.Sign(t, set)
			},
			code: ssf.ErrorCodeInvalidRequest,
		},
		{
			name: "complex member is not an object",
			token: func(t *testing.T) string {
				t.Helper()

				return transmitter.Sign(t, transmitter.NewSessionRevoked(ssftest.Subject{"format": "complex", "user": "user-1"}))
			},
			code: ssf.ErrorCodeInvalidRequest,
		},
		{
			name: "session member without id",
			token: func(t *testing.T) string {
				t.Helper()

				return transmitter.Sign(t, transmitter.NewSessionRevoked(ssftest.Complex(map[string]ssftest.Subject{
					"session": {"format": "opaque"},
				})))
			},
			code: ssf.ErrorCodeInvalidRequest,
		},
		{
			name: "missing sub_id",
			token: func(t *testing.T) string {
				t.Helper()

				return transmitter.Sign(t, transmitter.NewSessionRevoked(nil))
			},
			code: ssf.ErrorCodeInvalidRequest,
		},
		{
			name: "other event type is verified without parsing the subject",
			token: func(t *testing.T) string {
				t.Helper()

				return transmitter.Sign(t, transmitter.NewSET(ssftest.Opaque("x"), eventTypeCredentialChange, nil))
			},
		},
		{
			name: "typ with application prefix",
			token: func(t *testing.T) string {
				t.Helper()

				return transmitter.Sign(t, revoked(), ssftest.WithType("application/secevent+jwt"))
			},
			subject: ssf.Subject{Issuer: "https://idp.example.com", Subject: "user-1"},
		},
		{
			name: "wrong typ",
			token: func(t *testing.T) string {
				t.Helper()

				return transmitter.Sign(t, revoked(), ssftest.WithType("JWT"))
			},
			code: ssf.ErrorCodeInvalidRequest,
		},
		{
			name: "missing typ",
			token: func(t *testing.T) string {
				t.Helper()

				return transmitter.Sign(t, revoked(), ssftest.WithType(""))
			},
			code: ssf.ErrorCodeInvalidRequest,
		},
		{
			name: "unpublished key",
			token: func(t *testing.T) string {
				t.Helper()

				return transmitter.Sign(t, revoked(), ssftest.WithUnpublishedKey(t))
			},
			code: ssf.ErrorCodeInvalidKey,
		},
		{
			name: "HMAC",
			token: func(t *testing.T) string {
				t.Helper()

				return transmitter.Sign(t, revoked(), ssftest.WithSigningKey(jose.SigningKey{
					Algorithm: jose.HS256,
					Key:       []byte("0123456789abcdef0123456789abcdef"),
				}))
			},
			code: ssf.ErrorCodeInvalidRequest,
		},
		{
			name:  "not a JWS",
			token: func(*testing.T) string { return "not-a-jwt" },
			code:  ssf.ErrorCodeInvalidRequest,
		},
		{
			name: "wrong issuer",
			token: func(t *testing.T) string {
				t.Helper()

				set := revoked()
				set.Issuer = issuer + "/other"

				return transmitter.Sign(t, set)
			},
			code: ssf.ErrorCodeInvalidIssuer,
		},
		{
			name: "wrong audience",
			token: func(t *testing.T) string {
				t.Helper()

				set := revoked()
				set.Audience = ssftest.Audience{"https://other.example.com"}

				return transmitter.Sign(t, set)
			},
			code: ssf.ErrorCodeInvalidAudience,
		},
		{
			name: "audience array containing the stream audience",
			token: func(t *testing.T) string {
				t.Helper()

				set := revoked()
				set.Audience = ssftest.Audience{"https://other.example.com", ssftest.DefaultAudience}

				return transmitter.Sign(t, set)
			},
			subject: ssf.Subject{Issuer: "https://idp.example.com", Subject: "user-1"},
		},
		{
			name: "missing audience",
			token: func(t *testing.T) string {
				t.Helper()

				set := revoked()
				set.Audience = nil

				return transmitter.Sign(t, set)
			},
			code: ssf.ErrorCodeInvalidAudience,
		},
		{
			name: "malformed audience",
			token: func(t *testing.T) string {
				t.Helper()

				set := claims(t, revoked())
				set["aud"] = 42

				return transmitter.Sign(t, set)
			},
			code: ssf.ErrorCodeInvalidRequest,
		},
		{
			name: "stale iat",
			token: func(t *testing.T) string {
				t.Helper()

				set := revoked()
				set.IssuedAt = time.Now().Add(-2 * time.Hour).Unix()

				return transmitter.Sign(t, set)
			},
			code: ssf.ErrorCodeInvalidRequest,
		},
		{
			name: "future iat",
			token: func(t *testing.T) string {
				t.Helper()

				set := revoked()
				set.IssuedAt = time.Now().Add(10 * time.Minute).Unix()

				return transmitter.Sign(t, set)
			},
			code: ssf.ErrorCodeInvalidRequest,
		},
		{
			name: "iat within the clock skew",
			token: func(t *testing.T) string {
				t.Helper()

				set := revoked()
				set.IssuedAt = time.Now().Add(time.Minute).Unix()

				return transmitter.Sign(t, set)
			},
			subject: ssf.Subject{Issuer: "https://idp.example.com", Subject: "user-1"},
		},
		{
			name: "missing iat",
			token: func(t *testing.T) string {
				t.Helper()

				set := claims(t, revoked())
				delete(set, "iat")

				return transmitter.Sign(t, set)
			},
			code: ssf.ErrorCodeInvalidRequest,
		},
		{
			name: "negative iat",
			token: func(t *testing.T) string {
				t.Helper()

				set := revoked()
				set.IssuedAt = -1

				return transmitter.Sign(t, set)
			},
			code: ssf.ErrorCodeInvalidRequest,
		},
		{
			name: "missing jti",
			token: func(t *testing.T) string {
				t.Helper()

				set := revoked()
				set.JTI = ""

				return transmitter.Sign(t, set)
			},
			code: ssf.ErrorCodeInvalidRequest,
		},
		{
			name: "sub present",
			token: func(t *testing.T) string {
				t.Helper()

				set := claims(t, revoked())
				set["sub"] = "user-1"

				return transmitter.Sign(t, set)
			},
			code: ssf.ErrorCodeInvalidRequest,
		},
		{
			name: "exp present",
			token: func(t *testing.T) string {
				t.Helper()

				set := claims(t, revoked())
				set["exp"] = time.Now().Add(time.Hour).Unix()

				return transmitter.Sign(t, set)
			},
			code: ssf.ErrorCodeInvalidRequest,
		},
		{
			name: "two events",
			token: func(t *testing.T) string {
				t.Helper()

				set := revoked()
				set.Events[eventTypeCredentialChange] = map[string]any{}

				return transmitter.Sign(t, set)
			},
			code: ssf.ErrorCodeInvalidRequest,
		},
		{
			name: "no events",
			token: func(t *testing.T) string {
				t.Helper()

				set := revoked()
				set.Events = map[string]any{}

				return transmitter.Sign(t, set)
			},
			code: ssf.ErrorCodeInvalidRequest,
		},
		{
			name: "event is not an object",
			token: func(t *testing.T) string {
				t.Helper()

				set := revoked()
				set.Events = map[string]any{ssf.EventTypeSessionRevoked: "revoked"}

				return transmitter.Sign(t, set)
			},
			code: ssf.ErrorCodeInvalidRequest,
		},
		{
			name: "malformed event_timestamp",
			token: func(t *testing.T) string {
				t.Helper()

				set := revoked()
				set.Events = map[string]any{ssf.EventTypeSessionRevoked: map[string]any{"event_timestamp": -5}}

				return transmitter.Sign(t, set)
			},
			code: ssf.ErrorCodeInvalidRequest,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var modify []func(*ssf.VerifierConfig)
			if tc.modify != nil {
				modify = append(modify, tc.modify)
			}

			event, err := newVerifier(t, transmitter, modify...).Verify(t.Context(), tc.token(t))

			if tc.code == "" {
				require.NoError(t, err)
				assert.Equal(t, tc.subject, event.Subject)
				assert.NotEmpty(t, event.ID)
				assert.NotEmpty(t, event.TransactionID)
				assert.WithinDuration(t, time.Now(), event.IssuedAt, 2*time.Minute)

				return
			}

			var verifyErr *ssf.Error

			require.ErrorAs(t, err, &verifyErr)
			assert.Equal(t, tc.code, verifyErr.Code, err.Error())
			assert.NotEmpty(t, verifyErr.Description())
			assert.Zero(t, event)

			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
			}
		})
	}
}

func TestVerifySessionRevokedMembers(t *testing.T) {
	t.Parallel()

	transmitter := ssftest.New(t)
	set := transmitter.NewSessionRevoked(ssftest.IssSub("https://idp.example.com", "user-1"))
	set.Events[ssf.EventTypeSessionRevoked] = map[string]any{
		"event_timestamp":   1_700_000_000.5,
		"initiating_entity": "policy",
		"reason_admin":      map[string]string{"en": "Landspeed policy violation"},
	}

	event, err := newVerifier(t, transmitter).Verify(t.Context(), transmitter.Sign(t, set))
	require.NoError(t, err)

	assert.Equal(t, set.JTI, event.ID)
	assert.Equal(t, set.TXN, event.TransactionID)
	assert.Equal(t, ssf.EventTypeSessionRevoked, event.Type)
	assert.Equal(t, time.Unix(set.IssuedAt, 0), event.IssuedAt)
	assert.Equal(t, time.Unix(1_700_000_000, int64(500*time.Millisecond)), event.EventTimestamp)
	assert.Equal(t, "policy", event.InitiatingEntity)
	assert.Equal(t, map[string]string{"en": "Landspeed policy violation"}, event.ReasonAdmin)
	assert.False(t, event.Subject.SessionLevel())
}

func TestVerifyReplay(t *testing.T) {
	t.Parallel()

	transmitter := ssftest.New(t)
	verifier := newVerifier(t, transmitter)
	token := transmitter.Sign(t, transmitter.NewSessionRevoked(ssftest.IssSub("https://idp.example.com", "user-1")))

	// An event that was not processed is accepted again on redelivery.
	_, err := verifier.Verify(t.Context(), token)
	require.NoError(t, err)

	event, err := verifier.Verify(t.Context(), token)
	require.NoError(t, err)

	verifier.Processed(event)

	_, err = verifier.Verify(t.Context(), token)
	require.ErrorIs(t, err, ssf.ErrReplay)

	var verifyErr *ssf.Error

	require.ErrorAs(t, err, &verifyErr)
	assert.Equal(t, ssf.ErrorCodeInvalidRequest, verifyErr.Code)

	// Other SETs are not affected.
	_, err = verifier.Verify(t.Context(), transmitter.Sign(t, transmitter.NewSessionRevoked(ssftest.IssSub("https://idp.example.com", "user-1"))))
	require.NoError(t, err)
}

func TestVerifyKeyRotation(t *testing.T) {
	t.Parallel()

	transmitter := ssftest.New(t)
	verifier := newVerifier(t, transmitter)
	subject := ssftest.IssSub("https://idp.example.com", "user-1")

	_, err := verifier.Verify(t.Context(), transmitter.Sign(t, transmitter.NewSessionRevoked(subject)))
	require.NoError(t, err)

	transmitter.RotateKey(t)

	_, err = verifier.Verify(t.Context(), transmitter.Sign(t, transmitter.NewSessionRevoked(subject)))
	require.NoError(t, err, "an unknown kid must trigger a JWK Set refresh")
}

func TestErrorMessage(t *testing.T) {
	t.Parallel()

	transmitter := ssftest.New(t)
	set := transmitter.NewSessionRevoked(ssftest.IssSub("https://idp.example.com", "user-1"))
	set.Issuer = "https://other.example.com"

	_, err := newVerifier(t, transmitter).Verify(t.Context(), transmitter.Sign(t, set))

	var verifyErr *ssf.Error

	require.ErrorAs(t, err, &verifyErr)
	assert.Equal(t, "invalid_issuer: "+verifyErr.Description(), err.Error())
	assert.Contains(t, verifyErr.Description(), "https://other.example.com")
}
