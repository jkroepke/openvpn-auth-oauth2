package types

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
)

type URL struct {
	*url.URL
}

func NewURL(u string) (URL, error) {
	if u == "" {
		return URL{}, errors.New("empty URL")
	}

	stdURL, err := url.Parse(u)
	if err != nil {
		return URL{}, fmt.Errorf("failed to parse URL: %w", err)
	}

	return URL{stdURL}, nil
}

// IsEmpty checks if the URL is empty.
//
//goland:noinspection GoMixedReceiverTypes
func (u *URL) IsEmpty() bool {
	return u == nil || u.URL == nil || u.URL.String() == ""
}

// String returns the string representation of the URL.
//
//goland:noinspection GoMixedReceiverTypes
func (u URL) String() string {
	if u.IsEmpty() {
		return ""
	}

	return u.URL.String()
}

// MarshalText implements [encoding.TextMarshaler] interface.
//
//goland:noinspection GoMixedReceiverTypes
func (u URL) MarshalText() ([]byte, error) {
	return []byte(u.String()), nil
}

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
//
//goland:noinspection GoMixedReceiverTypes
func (u *URL) UnmarshalText(text []byte) error {
	parsedURL, err := NewURL(string(text))
	if err != nil {
		return err
	}

	*u = parsedURL

	return nil
}

// MarshalJSON implements the [json.Marshaler] interface.
//
//goland:noinspection GoMixedReceiverTypes
func (u *URL) MarshalJSON() ([]byte, error) {
	return json.Marshal(u.String()) //nolint:wrapcheck
}
