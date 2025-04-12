package client

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-auth-oauth2/management"
	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-auth-oauth2/util"
)

type Client struct {
	env util.List

	AuthFailedReasonFile string
	AuthPendingFile      string
	AuthControlFile      string
	ClientConfig         string

	ClientID      uint64 // A unique identifier for the client
	estimatedSize int    // Pre-calculated size for String() method
}

//nolint:cyclop
func NewClient(clientID uint64, envArray util.List) (*Client, error) {
	client := &Client{
		env:      envArray,
		ClientID: clientID,
		// Initialize base size: ">CLIENT:CONNECT," + "\r\n>CLIENT:ENV,END"
		estimatedSize: 17 + 18 + 2, // 35 base characters
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
	sb.WriteString(",0")

	for key, value := range c.env {
		sb.WriteString("\r\n>CLIENT:ENV,")
		sb.WriteString(key)
		sb.WriteString("=")
		sb.WriteString(value)
	}

	sb.WriteString("\r\n>CLIENT:ENV,END")

	return sb.String()
}

func (c *Client) WriteToAuthFile(auth string) error {
	if c.AuthControlFile == "" {
		return errors.New("auth_control_file not set")
	}

	if err := os.WriteFile(c.AuthControlFile, []byte(auth), 0o600); err != nil {
		return fmt.Errorf("write to file %s: %w", c.AuthControlFile, err)
	}

	return nil
}

// WriteAuthPending writes the auth_pending_file can be written, which causes the openvpn
// server to send a pending auth request to the client. See doc/management.txt
// for more details on this authentication mechanism. The format of the
// auth_pending_file is
// line 1: timeout in seconds
// line 2: Pending auth method the client needs to support (e.g. webauth)
// line 3: EXTRA (e.g. WEB_AUTH::http://www.example.com)
func (c *Client) WriteAuthPending(resp *management.Response) error {
	if c.AuthPendingFile != "" {
		pendingData := fmt.Sprintf("%s\nwebauth\n%s\n", resp.Timeout, resp.Message)
		if err := os.WriteFile(c.AuthPendingFile, []byte(pendingData), 0o600); err != nil {
			return fmt.Errorf("write to pending file %s: %w", c.AuthPendingFile, err)
		}
	}

	// Also write "2" to the auth control file to indicate deferred auth
	return c.WriteToAuthFile("2")
}
