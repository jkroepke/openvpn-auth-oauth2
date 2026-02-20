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
func (c *Client) AcceptClient(ctx context.Context, logger *slog.Logger, client state.ClientIdentifier, reAuth bool, username, clientConfigName string) {
	if reAuth {
		logger.LogAttrs(ctx, slog.LevelInfo, "client re-authentication")

		if _, err := c.SendCommandf(ctx, `client-auth-nt %d %d`, client.CID, client.KID); err != nil {
			logger.LogAttrs(ctx, slog.LevelWarn, "failed to accept client",
				slog.Any("error", err),
			)
		}

		return
	}

	c.acceptClientAuth(ctx, logger, client, username, clientConfigName)
}

//nolint:cyclop
func (c *Client) acceptClientAuth(ctx context.Context, logger *slog.Logger, client state.ClientIdentifier, username, clientConfigName string) {
	var (
		err           error
		tokenUsername string
	)

	logger.LogAttrs(ctx, slog.LevelInfo, "client authentication")

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

	if c.conf.OpenVPN.AuthTokenUser && client.UsernameIsDefined == 0 {
		tokenUsername = base64.StdEncoding.EncodeToString([]byte(username))
		if tokenUsername == "" {
			tokenUsername = "dXNlcm5hbWUK" // "username" //nolint:gosec // No hardcoded credentials
			username = "username"
		}
	}

	if c.conf.OpenVPN.OverrideUsername && username != "" {
		clientConfig = append(clientConfig, fmt.Sprintf(`override-username "%s"`, username))
	} else if tokenUsername != "" {
		clientConfig = append(clientConfig, fmt.Sprintf(`push "auth-token-user %s"`, tokenUsername))
	}

	if len(clientConfig) == 0 {
		_, err = c.SendCommandf(ctx, `client-auth-nt %d %d`, client.CID, client.KID)
	} else {
		sb := strings.Builder{}
		_, _ = fmt.Fprintf(&sb, "client-auth %d %d\r\n", client.CID, client.KID)

		for _, line := range clientConfig {
			sb.WriteString(strings.TrimSpace(line))
			sb.WriteString("\r\n")
		}

		sb.WriteString("END")

		_, err = c.SendCommand(ctx, sb.String(), false)
	}

	if err != nil {
		logger.LogAttrs(ctx, slog.LevelWarn, "failed to accept client",
			slog.Any("error", err),
		)
	}
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
		return make([]string, 0), nil
	}

	clientConfigFile, err := c.conf.OpenVPN.ClientConfig.Path.Open(username + ".conf")
	if err != nil {
		return make([]string, 0), fmt.Errorf("failed to open client config file: %w", err)
	}

	clientConfigBytes, err := io.ReadAll(clientConfigFile)
	if err != nil {
		return make([]string, 0), fmt.Errorf("failed to read client config file: %w", err)
	}

	return strings.Split(strings.TrimSpace(strings.ReplaceAll(string(clientConfigBytes), "\r", "")), "\n"), nil
}
