package util

import "C"

import (
	"errors"
	"fmt"
	"strings"
	"unsafe"
)

var (
	// ErrInvalidPointer is returned when the provided pointer is invalid.
	ErrInvalidPointer = errors.New("invalid pointer provided")
	// ErrMalformedEnvVar is returned when an environment variable is malformed.
	ErrMalformedEnvVar = errors.New("malformed environment variable")
)

type List map[string]string

const MaxEnvVars = 128 // Maximum number of environment variables to process

func NewEnvList(ptr unsafe.Pointer) (List, error) {
	if ptr == nil || uintptr(ptr) == 0 {
		return nil, ErrInvalidPointer
	}

	envVarsChar := (*[MaxEnvVars]*C.char)(ptr)

	envArray := make(List)

	// Iterate through NULL-terminated array
	for i := 0; i < MaxEnvVars && envVarsChar[i] != nil; i++ {
		envStr := C.GoString(envVarsChar[i])

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
