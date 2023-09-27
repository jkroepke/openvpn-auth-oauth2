package utils

import "net/url"

func IsUrlEmpty(url *url.URL) bool {
	return url == nil || url.String() == ""
}
