package utils

import "net/url"

func IsURLEmpty(url *url.URL) bool {
	return url == nil || url.String() == ""
}
