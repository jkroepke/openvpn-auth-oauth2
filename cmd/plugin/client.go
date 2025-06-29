//go:build linux

package main

import "C"

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"unsafe"
)

const MaxEnvVars = 128 // Maximum number of environment variables to process

var (
	// ErrInvalidPointer is returned when the provided pointer is invalid
	ErrInvalidPointer = errors.New("invalid pointer provided")
	// ErrMalformedEnvVar is returned when an environment variable is malformed
	ErrMalformedEnvVar = errors.New("malformed environment variable")

	// ClientID is a global counter for client IDs, incremented atomically
	ClientID uint64
	KeyIDs   = make(map[string]uint64) // Map to store key IDs for clients
)

func NewClientID() uint64 {
	return atomic.AddUint64(&ClientID, 1)
}

type Client struct {
	ClientID             uint64 // A unique identifier for the client
	AuthFailedReasonFile string
	AuthPendingFile      string
	AuthControlFile      string
	IpAddr               string
	IpPort               string
	CommonName           string
	Username             string
}

func NewClient(envp unsafe.Pointer) (Client, error) {
	if envp == nil {
		return Client{}, ErrInvalidPointer
	}

	// Cast to array of C string pointers
	envArray := (*[MaxEnvVars]*C.char)(envp)
	var client Client

	// Iterate through NULL-terminated array
	for i := 0; i < MaxEnvVars && envArray[i] != nil; i++ {
		envStr := C.GoString(envArray[i])
		if err := client.parseEnvVar(envStr); err != nil {
			// Log error but continue processing
			// In production, you might want to use a proper logger
			return Client{}, fmt.Errorf("failed to parse env var %q: %w", envStr, err)
		}
	}

	client.ClientID = NewClientID()

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
	case "untrusted_ip":
		c.IpAddr = value
	case "untrusted_ip6":
		// Handle IPv6, might want to validate format
		c.IpAddr = value
	case "untrusted_port":
		c.IpPort = value
	case "common_name":
		c.CommonName = value
	case "username":
		c.Username = value
	default:
		// Unknown environment variable - not an error, just ignore
		return nil
	}

	return nil
}

func (c *Client) String() string {
	sb := strings.Builder{}
	sb.WriteString(">CLIENT:CONNECT,")
	sb.WriteString(strconv.FormatUint(c.ClientID, 10))
	sb.WriteString(",1\r\n>CLIENT:ENV,username=")
	sb.WriteString(c.Username)
	sb.WriteString("\r\n>CLIENT:ENV,common_name=")
	sb.WriteString(c.CommonName)

	if strings.Contains(c.IpAddr, ":") {
		sb.WriteString("\r\n>CLIENT:ENV,untrusted_ip6=")
		sb.WriteString(c.IpAddr)
	} else {
		sb.WriteString("\r\n>CLIENT:ENV,untrusted_ip=")
		sb.WriteString(c.IpAddr)
	}

	sb.WriteString("\r\n>CLIENT:ENV,untrusted_port=")
	sb.WriteString(c.IpPort)
	sb.WriteString("\n\n>CLIENT:ENV,X509_0_CN=")
	sb.WriteString("\n\n>CLIENT:ENV,password=")
	sb.WriteString("\n\n>CLIENT:ENV,IV_SSO=webauth,openurl,crtext")
	sb.WriteString("\r\n>CLIENT:ENV,END")

	return sb.String()
}
