package config

import (
	"encoding/json"
	"fmt"
	"net/url"
)

type URL url.URL

func NewURL(u string) (*URL, error) {
	stdURL, err := url.Parse(u)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}

	return (*URL)(stdURL), nil
}

func (u *URL) IsEmpty() bool {
	return u == nil || u.String() == ""
}

func (u *URL) String() string {
	return u.URL().String()
}

func (u *URL) URL() *url.URL {
	return (*url.URL)(u)
}

func (u *URL) JoinPath(elem ...string) *URL {
	return (*URL)(u.URL().JoinPath(elem...))
}

func (u *URL) MarshalText() ([]byte, error) {
	return []byte(u.String()), nil
}

func (u *URL) UnmarshalText(text []byte) error {
	parsedURL, err := url.Parse(string(text))
	if err != nil {
		return err
	}

	*u = URL(*parsedURL)

	return nil
}

func (u *URL) MarshalJSON() ([]byte, error) {
	return json.Marshal(u.String())
}
