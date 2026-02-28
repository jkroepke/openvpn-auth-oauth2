package openvpn

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
)

// AcceptClient accepts an OpenVPN client connection.
// It reads the client configuration from the CCD path if enabled.
func (c *Client) AcceptClient(ctx context.Context, logger *slog.Logger, client state.ClientIdentifier, username, clientConfigName string) {
	logger.LogAttrs(ctx, slog.LevelInfo, "client authentication")

	clientConfig := c.loadClientConfig(ctx, logger, client, clientConfigName, username)

	err := c.sendClientAuth(ctx, client, clientConfig)
	if err != nil {
		logger.LogAttrs(ctx, slog.LevelWarn, "failed to accept client",
			slog.Any("error", err),
		)
	}
}

// loadClientConfig reads the client configuration from CCD and logs the result.
func (c *Client) loadClientConfig(ctx context.Context, logger *slog.Logger, client state.ClientIdentifier, clientConfigName, username string) []string {
	clientConfig, err := c.readClientConfig(clientConfigName)

	switch {
	case err != nil:
		logger.LogAttrs(ctx, slog.LevelDebug, "failed to read client config",
			slog.String("config", clientConfigName),
			slog.Any("error", err),
		)
	case len(clientConfig) > 0:
		logger.LogAttrs(ctx, slog.LevelDebug, "applying client config from CCD",
			slog.String("config", clientConfigName),
			slog.Any("content", clientConfig),
		)
	default:
		logger.LogAttrs(ctx, slog.LevelInfo, "no client config found in CCD",
			slog.String("config", clientConfigName),
		)
	}

	if !c.conf.OAuth2.Refresh.ValidateUser {
		return clientConfig
	}

	if c.conf.OpenVPN.OverrideUsername {
		clientConfig = append(clientConfig, fmt.Sprintf(`override-username %q`, username))
	} else if c.conf.OpenVPN.AuthTokenUser && client.UsernameIsDefined == 0 {
		if len(username) == 0 {
			username = "username"
		}

		clientConfig = append(clientConfig, fmt.Sprintf(`push "auth-token-user %s"`, base64.StdEncoding.EncodeToString([]byte(username))))
	}

	return clientConfig
}

// sendClientAuth sends the appropriate client-auth or client-auth-nt command.
func (c *Client) sendClientAuth(ctx context.Context, client state.ClientIdentifier, clientConfig []string) error {
	if len(clientConfig) == 0 {
		_, err := c.SendCommandf(ctx, `client-auth-nt %d %d`, client.CID, client.KID)

		return err
	}

	sb := strings.Builder{}
	_, _ = fmt.Fprintf(&sb, "client-auth %d %d\r\n", client.CID, client.KID)

	for _, line := range clientConfig {
		sb.WriteString(strings.TrimSpace(line))
		sb.WriteString("\r\n")
	}

	sb.WriteString("END")

	_, err := c.SendCommand(ctx, sb.String(), false)

	return err
}

func (c *Client) DenyClient(ctx context.Context, logger *slog.Logger, client state.ClientIdentifier, reason string) {
	logger.LogAttrs(ctx, slog.LevelInfo, fmt.Sprintf("deny OpenVPN client cid %d, kid %d", client.CID, client.KID))

	_, err := c.SendCommandf(ctx, `client-deny %d %d "%s"`, client.CID, client.KID, reason)
	if err != nil {
		logger.LogAttrs(ctx, slog.LevelWarn, "failed to deny client",
			slog.Any("error", err),
		)
	}
}

func (c *Client) readClientConfig(username string) ([]string, error) {
	if !c.conf.OpenVPN.ClientConfig.Enabled || c.conf.OpenVPN.ClientConfig.Path.IsEmpty() || len(username) == 0 {
		return make([]string, 0, 1), nil
	}

	clientConfigFile, err := c.conf.OpenVPN.ClientConfig.Path.Open(username + ".conf")
	if err != nil {
		return nil, fmt.Errorf("failed to open client config file: %w", err)
	}

	clientConfigBytes, err := io.ReadAll(clientConfigFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read client config file: %w", err)
	}

	content := strings.TrimSpace(strings.ReplaceAll(string(clientConfigBytes), "\r", ""))

	// Pre-allocate with exact line count + 1 spare capacity for applyUsernameConfig.
	n := strings.Count(content, "\n") + 1
	result := make([]string, 0, n+1)

	for {
		i := strings.IndexByte(content, '\n')
		if i < 0 {
			result = append(result, content)

			break
		}

		result = append(result, content[:i])
		content = content[i+1:]
	}

	return result, nil
}
