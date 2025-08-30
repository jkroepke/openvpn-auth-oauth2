//go:build linux

package client

import "C"

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
)

const MaxEnvVars = 128 // Maximum number of environment variables to process

var (
	// ErrInvalidPointer is returned when the provided pointer is invalid
	ErrInvalidPointer = errors.New("invalid pointer provided")
	// ErrMalformedEnvVar is returned when an environment variable is malformed
	ErrMalformedEnvVar = errors.New("malformed environment variable")

	// clientID is a global counter for client IDs, incremented atomically
	clientID uint64
)

type Client struct {
	ClientID             uint64 // A unique identifier for the client
	AuthFailedReasonFile string
	AuthPendingFile      string
	AuthControlFile      string
	Env                  map[string]string
	estimatedSize        int // Pre-calculated size for String() method
}

func NewClient(envArray *[MaxEnvVars]*C.char) (*Client, error) {
	client := &Client{
		Env: make(map[string]string),
		// Initialize base size: ">CLIENT:CONNECT," + "\r\n>CLIENT:ENV,END"
		estimatedSize: 17 + 18, // 35 base characters
	}

	// Iterate through NULL-terminated array
	for i := 0; i < MaxEnvVars && envArray[i] != nil; i++ {
		envStr := C.GoString(envArray[i])
		if err := client.parseEnvVar(envStr); err != nil {
			// Log error but continue processing
			// In production, you might want to use a proper logger
			return nil, fmt.Errorf("failed to parse env var %q: %w", envStr, err)
		}
	}

	client.ClientID = atomic.AddUint64(&clientID, 1)

	// Add the length of the client ID to the estimated size
	client.estimatedSize += len(strconv.FormatUint(client.ClientID, 10))

	return client, nil
}

// parseEnvVar parses a single environment variable in KEY=VALUE format
func (c *Client) parseEnvVar(envVar string) error {
	if envVar == "" {
		return nil // Skip empty strings
	}

	parts := strings.SplitN(envVar, "=", 2)
	if len(parts) != 2 {
		return fmt.Errorf("%w: %q (missing '=')", ErrMalformedEnvVar, envVar)
	}

	key, value := strings.TrimSpace(parts[0]), parts[1]
	if key == "" {
		return fmt.Errorf("%w: %q (empty key)", ErrMalformedEnvVar, envVar)
	}

	return c.setField(key, value)
}

// setField sets the appropriate client field based on the environment variable key
func (c *Client) setField(key, value string) error {
	switch key {
	case "auth_failed_reason_file":
		c.AuthFailedReasonFile = value
	case "auth_pending_file":
		c.AuthPendingFile = value
	case "auth_control_file":
		c.AuthControlFile = value
	default:
		c.Env[key] = value

		// Incrementally calculate the estimated size
		c.estimatedSize += len(key) + len(value) + 15 // 15 is for the additional formatting characters
	}

	return nil
}

func (c *Client) String() string {
	if c == nil {
		return ""
	}

	sb := strings.Builder{}
	sb.Grow(c.estimatedSize) // Use the pre-calculated size

	sb.WriteString(">CLIENT:CONNECT,")
	sb.WriteString(strconv.FormatUint(c.ClientID, 10))

	for key, value := range c.Env {
		sb.WriteString("\r\n>CLIENT:ENV,")
		sb.WriteString(key)
		sb.WriteString("=")
		sb.WriteString(value)
	}

	sb.WriteString("\r\n>CLIENT:ENV,END")

	return sb.String()
}
