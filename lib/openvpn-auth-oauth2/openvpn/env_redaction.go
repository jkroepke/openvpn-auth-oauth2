//go:build (darwin || linux || openbsd || freebsd) && cgo

package openvpn

import (
	"strings"
	"unicode"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/lib/openvpn-auth-oauth2/util"
)

const redactedEnvValue = "***"

func redactedEnvList(env util.List) util.List {
	redacted := make(util.List, len(env))

	for key, value := range env {
		key = sanitizeEnvLogValue(key)

		if sensitiveEnvKey(key) {
			value = redactedEnvValue
		} else {
			value = sanitizeEnvLogValue(value)
		}

		redacted[key] = value
	}

	return redacted
}

func sensitiveEnvKey(key string) bool {
	key = strings.ToLower(key)

	return strings.Contains(key, "password") ||
		strings.Contains(key, "token") ||
		strings.Contains(key, "secret")
}

func sanitizeEnvLogValue(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '?'
		}

		return r
	}, value)
}
