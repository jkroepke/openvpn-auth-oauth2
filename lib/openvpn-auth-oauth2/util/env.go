package util

import "C"

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

// NewEnvList converts a NULL-terminated C string array of environment variables into a Go map.
//
// The function expects environment variables in the standard "KEY=value" format, where:
//   - Each string in the array should contain exactly one '=' character
//   - The key (before '=') is trimmed of leading/trailing whitespace
//   - The value (after '=') is preserved as-is, including any whitespace or additional '=' characters
//   - Empty strings in the array are silently skipped
//
// Example input:
//
//	["PATH=/usr/bin:/bin", "USER=testuser", "HOME=/home/user", NULL]
//
// Returns a map:
//
//	{"PATH": "/usr/bin:/bin", "USER": "testuser", "HOME": "/home/user"}
//
// Parameters:
//   - envVarsChar: A pointer to a NULL-terminated array of C strings, where each string
//     represents an environment variable in KEY=value format
//
// Returns:
//   - List: A map containing the parsed environment variables
//   - error: An error if the pointer is nil (ErrInvalidPointer) or if any variable
//     is malformed (ErrMalformedEnvVar)
//
// Errors:
//   - ErrInvalidPointer: returned when envVarsChar is nil
//   - ErrMalformedEnvVar: returned when a variable is missing '=' or has an empty key
//
// Note: If duplicate keys are present (after trimming whitespace), the last occurrence wins.
func NewEnvList(envVarsChar **c.Char) (List, error) {
	if envVarsChar == nil {
		return nil, ErrInvalidPointer
	}

	// Count
	count := 0
	for p := envVarsChar; *p != nil; p = (**c.Char)(unsafe.Add(unsafe.Pointer(p), unsafe.Sizeof(*p))) {
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

		// Skip empty entries (empty strings)
		if key != "" {
			envArray[key] = value
		}
	}

	return envArray, nil
}

// parseEnvVar parses a single environment variable string in KEY=value format.
//
// The function splits the input string on the first '=' character and returns
// the key and value separately.
// The key is trimmed of leading and trailing
// whitespace, while the value is preserved exactly as provided.
//
// Special cases:
//   - Empty strings return empty key and value with no error (caller should skip)
//   - Keys with only whitespace are rejected as malformed
//   - Values may contain '=' characters (e.g., "EQUATION=x=y+z")
//   - Values may be empty (e.g., "EMPTY_VAR=")
//
// Parameters:
//   - envVar: A string in KEY=value format
//
// Returns:
//   - string: The trimmed key
//   - string: The value (untrimmed)
//   - error: An error if the variable is malformed (ErrMalformedEnvVar)
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
