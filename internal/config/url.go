package config

import "net/url"

func IsURLEmpty(u *url.URL) bool {
	return u == nil || u.String() == ""
}
