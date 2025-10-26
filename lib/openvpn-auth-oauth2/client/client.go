package client

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-auth-oauth2/management"
	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-auth-oauth2/util"
)

const (
	AuthControlFileEnvKey      = "auth_control_file"
	AuthPendingFileEnvKey      = "auth_pending_file"
	AuthFailedReasonFileEnvKey = "auth_failed_reason_file"
)

var (
	ErrAuthControlFileNotSet = errors.New("auth_control_file not set")
	ErrAuthPendingFileNotSet = errors.New("auth_pending_file not set")
)

type Client struct {
	env util.List

	AuthFailedReasonFile string
	AuthPendingFile      string
	AuthControlFile      string
	ClientConfig         string

	ClientID      uint64 // A unique identifier for the client
	estimatedSize int    // Pre-calculated size for GetConnectMessage() method
}

//nolint:cyclop
func NewClient(clientID uint64, envArray util.List) (*Client, error) {
	client := &Client{
		env:      envArray,
		ClientID: clientID,
		// Initialize base size: "\r\n>CLIENT:ENV,END"
		estimatedSize: 19,
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
		case AuthFailedReasonFileEnvKey:
			client.AuthFailedReasonFile = value
		case AuthPendingFileEnvKey:
			client.AuthPendingFile = value
		case AuthControlFileEnvKey:
			client.AuthControlFile = value
		default:
			client.estimatedSize += len(key) + len(value) + 15
		}
	}

	return client, nil
}

func (c *Client) GetConnectMessage() string {
	clientID := strconv.FormatUint(c.ClientID, 10)
	connectionID := strconv.FormatInt(time.Now().Unix(), 10)

	sb := strings.Builder{}
	sb.Grow(16 + len(clientID) + 1 + len(connectionID) + c.estimatedSize) // Use the pre-calculated size

	sb.WriteString(">CLIENT:CONNECT,")
	sb.WriteString(clientID)
	sb.WriteString(",")
	sb.WriteString(connectionID)

	for key, value := range c.env {
		if key == AuthControlFileEnvKey || key == AuthPendingFileEnvKey || key == AuthFailedReasonFileEnvKey {
			continue
		}

		sb.WriteString("\r\n>CLIENT:ENV,")
		sb.WriteString(key)
		sb.WriteString("=")
		sb.WriteString(value)
	}

	sb.WriteString("\r\n>CLIENT:ENV,END")

	return sb.String()
}

func (c *Client) GetDisconnectMessage() string {
	clientID := strconv.FormatUint(c.ClientID, 10)

	sb := strings.Builder{}
	sb.Grow(c.estimatedSize + 4 + len(clientID))

	sb.WriteString(">CLIENT:DISCONNECT,")
	sb.WriteString(clientID)

	for key, value := range c.env {
		if key == AuthControlFileEnvKey || key == AuthPendingFileEnvKey || key == AuthFailedReasonFileEnvKey {
			continue
		}

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
		return ErrAuthControlFileNotSet
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
	if c.AuthPendingFile == "" {
		return ErrAuthPendingFileNotSet
	}

	pendingData := fmt.Sprintf("%s\nwebauth\n%s\n", resp.Timeout, resp.Message)
	if err := os.WriteFile(c.AuthPendingFile, []byte(pendingData), 0o600); err != nil {
		return fmt.Errorf("write to pending file %s: %w", c.AuthPendingFile, err)
	}

	// Also write "2" to the auth control file to indicate deferred auth
	return c.WriteToAuthFile("2")
}
