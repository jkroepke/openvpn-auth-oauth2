package ssf

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
)

// Subject identifier formats (RFC 9493) and complex subject members (SSF 1.0,
// section 3.3) the receiver understands.
const (
	FormatIssSub  = "iss_sub"
	FormatEmail   = "email"
	FormatOpaque  = "opaque"
	FormatComplex = "complex"

	MemberUser    = "user"
	MemberSession = "session"

	memberFormat = "format"

	// allSessions is the opaque session id Keycloak sends when an
	// administrator signs a user out of all sessions. It names no session, so
	// such an event is user level.
	allSessions = "ALL"
)

// Subject is the principal of an event, reduced to the fields a session can be
// matched by. A Subject with a SessionID is session-level; without one it
// names a user and is user-level.
type Subject struct {
	// Issuer and Subject come from an iss_sub identifier. Issuer is the issuer
	// of the user's identity, not the issuer of the SET.
	Issuer  string
	Subject string
	// Email comes from an email identifier.
	Email string
	// SessionID is the id of an opaque session member of a complex subject.
	SessionID string
}

// SessionLevel reports whether the subject names a single session.
func (s Subject) SessionLevel() bool {
	return s.SessionID != ""
}

type subjectParser struct {
	critical   []string
	allowEmail bool
}

// parse parses an RFC 9493 subject identifier as SSF 1.0 uses it in sub_id.
func (p subjectParser) parse(raw json.RawMessage) (Subject, error) {
	members, format, err := decodeIdentifier(raw)
	if err != nil {
		return Subject{}, err
	}

	if format == FormatComplex {
		return p.parseComplex(members)
	}

	return p.parseUser(format, members)
}

// parseUser parses a simple identifier that names a user.
func (p subjectParser) parseUser(format string, members map[string]json.RawMessage) (Subject, error) {
	switch format {
	case FormatIssSub:
		issuer, err := requiredString(members, "iss")
		if err != nil {
			return Subject{}, err
		}

		subject, err := requiredString(members, "sub")
		if err != nil {
			return Subject{}, err
		}

		return Subject{Issuer: issuer, Subject: subject}, nil
	case FormatEmail:
		if !p.allowEmail {
			return Subject{}, fmt.Errorf("%w: email subjects are disabled", ErrUnsupportedSubject)
		}

		email, err := requiredString(members, "email")
		if err != nil {
			return Subject{}, err
		}

		return Subject{Email: email}, nil
	default:
		return Subject{}, fmt.Errorf("%w: format %q", ErrUnsupportedSubject, format)
	}
}

// parseComplex parses a complex subject. The user and session members are
// used; any other member is ignored unless the transmitter lists it as
// critical, in which case the event must be discarded (SSF 1.0, section 3.6).
func (p subjectParser) parseComplex(members map[string]json.RawMessage) (Subject, error) {
	var (
		subject Subject
		found   bool
	)

	for name, raw := range members {
		used, err := p.parseMember(&subject, name, raw)
		if err != nil {
			return Subject{}, fmt.Errorf("member %q: %w", name, err)
		}

		found = found || used
	}

	if !found {
		return Subject{}, fmt.Errorf("%w: complex subject without a user or session member", ErrUnsupportedSubject)
	}

	if subject.SessionID == allSessions && (subject.Subject != "" || subject.Email != "") {
		subject.SessionID = ""
	}

	return subject, nil
}

// parseMember applies the complex subject member name to subject and reports
// whether the member was used.
func (p subjectParser) parseMember(subject *Subject, name string, raw json.RawMessage) (bool, error) {
	switch name {
	case MemberUser:
		members, format, err := decodeIdentifier(raw)
		if err != nil {
			return false, err
		}

		user, err := p.parseUser(format, members)
		if err != nil {
			return false, err
		}

		subject.Issuer, subject.Subject, subject.Email = user.Issuer, user.Subject, user.Email

		return true, nil
	case MemberSession:
		sessionID, err := parseSession(raw)
		if err != nil {
			return false, err
		}

		subject.SessionID = sessionID

		return true, nil
	case memberFormat:
		return false, nil
	default:
		if slices.Contains(p.critical, name) {
			return false, fmt.Errorf("%w: critical member", ErrUnsupportedSubject)
		}

		return false, nil
	}
}

// parseSession parses the session member of a complex subject, which must be
// an opaque identifier.
func parseSession(raw json.RawMessage) (string, error) {
	members, format, err := decodeIdentifier(raw)
	if err != nil {
		return "", err
	}

	if format != FormatOpaque {
		return "", fmt.Errorf("%w: session format %q", ErrUnsupportedSubject, format)
	}

	return requiredString(members, "id")
}

// decodeIdentifier decodes a subject identifier object and returns its members
// and format.
func decodeIdentifier(raw json.RawMessage) (map[string]json.RawMessage, string, error) {
	var members map[string]json.RawMessage

	if err := json.Unmarshal(raw, &members); err != nil || members == nil {
		return nil, "", errors.New("subject identifier is not a JSON object")
	}

	format, err := requiredString(members, memberFormat)
	if err != nil {
		return nil, "", err
	}

	return members, format, nil
}

// requiredString returns the non-empty string member name.
func requiredString(members map[string]json.RawMessage, name string) (string, error) {
	var value string

	if raw, ok := members[name]; ok {
		if err := json.Unmarshal(raw, &value); err != nil {
			return "", fmt.Errorf("subject member %q is not a string", name)
		}
	}

	if value == "" {
		return "", fmt.Errorf("subject member %q is missing", name)
	}

	return value, nil
}
