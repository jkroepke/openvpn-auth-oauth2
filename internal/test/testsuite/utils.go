package testsuite

import (
	"strings"
)

func GetAuthURLFromMessage(message string) string {
	_, message, _ = strings.Cut(message, `"`)
	message, _, _ = strings.Cut(message, `"`)

	return strings.TrimPrefix(message, "WEB_AUTH::")
}
