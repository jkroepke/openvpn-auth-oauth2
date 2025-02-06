package config

import (
	"encoding/json"
	"net/url"
)

type URL url.URL

func IsURLEmpty(u *url.URL) bool {
	return u == nil || u.String() == ""
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
