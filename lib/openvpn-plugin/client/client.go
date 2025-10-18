//go:build linux

package client

import (
	"strconv"
	"strings"
)

type Client struct {
	env map[string]string

	AuthFailedReasonFile string
	AuthPendingFile      string
	AuthControlFile      string
	ClientConfig         string

	ClientID      uint64 // A unique identifier for the client
	estimatedSize int    // Pre-calculated size for String() method
}

//nolint:cyclop
func NewClient(clientID uint64, envArray map[string]string) (*Client, error) {
	client := &Client{
		env:      envArray,
		ClientID: clientID,
		// Initialize base size: ">CLIENT:CONNECT," + "\r\n>CLIENT:ENV,END"
		estimatedSize: 17 + 18, // 35 base characters
	}

	if clientID >= 10_000 {
		client.estimatedSize += len(strconv.FormatUint(clientID, 10))
	} else {
		switch {
		case clientID >= 1_000:
			client.estimatedSize += 4
		case clientID >= 100:
			client.estimatedSize += 3
		case clientID >= 10:
			client.estimatedSize += 2
		default:
			client.estimatedSize++
		}
	}

	for key, value := range envArray {
		switch key {
		case "auth_failed_reason_file":
			client.AuthFailedReasonFile = value
		case "auth_pending_file":
			client.AuthPendingFile = value
		case "auth_control_file":
			client.AuthControlFile = value
		default:
			client.estimatedSize += len(key) + len(value) + 15
		}
	}

	return client, nil
}

func (c *Client) String() string {
	if c == nil {
		return ""
	}

	sb := strings.Builder{}
	sb.Grow(c.estimatedSize) // Use the pre-calculated size

	sb.WriteString(">CLIENT:CONNECT,")
	sb.WriteString(strconv.FormatUint(c.ClientID, 10))

	for key, value := range c.env {
		sb.WriteString("\r\n>CLIENT:ENV,")
		sb.WriteString(key)
		sb.WriteString("=")
		sb.WriteString(value)
	}

	sb.WriteString("\r\n>CLIENT:ENV,END")

	return sb.String()
}
