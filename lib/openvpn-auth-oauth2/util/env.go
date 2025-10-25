package util

import (
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-auth-oauth2/c"
)

var (
	// ErrInvalidPointer is returned when the provided pointer is invalid.
	ErrInvalidPointer = errors.New("invalid pointer provided")
	// ErrMalformedEnvVar is returned when an environment variable is malformed.
	ErrMalformedEnvVar = errors.New("malformed environment variable")
)

type List map[string]string

func NewEnvList(envVarsChar **c.Char) (List, error) {
	if envVarsChar == nil {
		return nil, ErrInvalidPointer
	}

	// Count
	count := 0
	for p := envVarsChar; *p != nil; p = (**c.Char)(unsafe.Pointer(uintptr(unsafe.Pointer(p)) + unsafe.Sizeof(*p))) {
		count++
	}

	ptrs := unsafe.Slice(envVarsChar, count)
	envArray := make(List, count)

	// Iterate through NULL-terminated array
	for _, s := range ptrs {
		envStr := c.GoString(s)

		key, value, err := parseEnvVar(envStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse env var %q: %w", envStr, err)
		}

		envArray[key] = value
	}

	return envArray, nil
}

func parseEnvVar(envVar string) (string, string, error) {
	if envVar == "" {
		return "", "", nil // Skip empty strings
	}

	parts := strings.SplitN(envVar, "=", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("%w: %q (missing '=')", ErrMalformedEnvVar, envVar)
	}

	key, value := strings.TrimSpace(parts[0]), parts[1]
	if key == "" {
		return "", "", fmt.Errorf("%w: %q (empty key)", ErrMalformedEnvVar, envVar)
	}

	return key, value, nil
}
