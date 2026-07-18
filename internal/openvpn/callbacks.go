package openvpn

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"strings"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/openvpn/connection"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/state"
)

const clientKillFailedResponse = "ERROR: client-kill command failed"

// AcceptClient accepts an OpenVPN client connection.
// It reads the client configuration from the CCD path if enabled.
func (c *Client) AcceptClient(ctx context.Context, logger *slog.Logger, client state.ClientIdentifier, username string, clientConfigNames ...string) error {
	logger.LogAttrs(ctx, slog.LevelInfo, "client authentication")

	clientConfig, err := c.loadClientConfig(ctx, logger, client, clientConfigNames, username)
	if err != nil {
		logger.LogAttrs(
			ctx, slog.LevelWarn, "failed to load client config",
			slog.Any("error", err),
		)
		c.DenyClient(ctx, logger, client, "client configuration not found")

		return err
	}

	err = c.sendClientAuth(ctx, client, clientConfig)
	if err != nil {
		logger.LogAttrs(
			ctx, slog.LevelWarn, "failed to accept client",
			slog.Any("error", err),
		)
	}

	return err
}

// loadClientConfig reads the client configuration from CCD and logs the result.
func (c *Client) loadClientConfig(
	ctx context.Context, logger *slog.Logger, client state.ClientIdentifier, clientConfigNames []string, username string,
) ([]string, error) {
	var clientConfig []string

	if !c.conf.OpenVPN.ClientConfig.Enabled {
		return c.applyUsernameConfig(clientConfig, client, username), nil
	}

	if len(clientConfigNames) == 0 {
		clientConfigNames = []string{"DEFAULT"}
	}

	if c.conf.OpenVPN.ClientConfig.Strategy != config.OpenVPNConfigStrategyMerge {
		clientConfigNames = clientConfigNames[:1]
	}

	clientConfig, err := c.readClientConfigs(ctx, logger, clientConfigNames)
	if err != nil {
		return nil, err
	}

	return c.applyUsernameConfig(clientConfig, client, username), nil
}

func (c *Client) applyUsernameConfig(clientConfig []string, client state.ClientIdentifier, username string) []string {
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

func (c *Client) readClientConfigs(ctx context.Context, logger *slog.Logger, clientConfigNames []string) ([]string, error) {
	if c.conf.OpenVPN.ClientConfig.Strategy != config.OpenVPNConfigStrategyMerge {
		return c.readSingleClientConfig(ctx, logger, clientConfigNames[0])
	}

	seenConfigNames := make(map[string]struct{}, len(clientConfigNames))
	seenLines := make(map[string]struct{})
	clientConfig := make([]string, 0, len(clientConfigNames))

	for _, clientConfigName := range clientConfigNames {
		if _, ok := seenConfigNames[clientConfigName]; ok {
			continue
		}

		seenConfigNames[clientConfigName] = struct{}{}

		configLines, err := c.readClientConfig(clientConfigName)
		if err != nil {
			skip, err := c.handleClientConfigReadError(ctx, logger, clientConfigName, err)
			if err != nil {
				return nil, err
			}

			if skip {
				continue
			}
		} else {
			c.logClientConfigRead(ctx, logger, clientConfigName, configLines, nil)
		}

		if len(configLines) == 0 {
			continue
		}

		for _, line := range configLines {
			if _, ok := seenLines[line]; ok {
				continue
			}

			seenLines[line] = struct{}{}
			clientConfig = append(clientConfig, line)
		}
	}

	return clientConfig, nil
}

func (c *Client) readSingleClientConfig(ctx context.Context, logger *slog.Logger, clientConfigName string) ([]string, error) {
	clientConfig, err := c.readClientConfig(clientConfigName)
	if err != nil {
		_, err := c.handleClientConfigReadError(ctx, logger, clientConfigName, err)
		if err != nil {
			return nil, err
		}

		return nil, nil
	}

	c.logClientConfigRead(ctx, logger, clientConfigName, clientConfig, nil)

	return clientConfig, nil
}

func (c *Client) handleClientConfigReadError(ctx context.Context, logger *slog.Logger, clientConfigName string, err error) (bool, error) {
	if !errors.Is(err, fs.ErrNotExist) {
		c.logClientConfigRead(ctx, logger, clientConfigName, nil, err)

		return true, nil
	}

	logger.LogAttrs(
		ctx, slog.LevelDebug, "client config file not found",
		slog.String("config", clientConfigName),
	)

	if !c.conf.OpenVPN.ClientConfig.IgnoreNotFound {
		return false, err
	}

	return true, nil
}

func (c *Client) logClientConfigRead(ctx context.Context, logger *slog.Logger, clientConfigName string, clientConfig []string, err error) {
	switch {
	case err != nil:
		logger.LogAttrs(
			ctx, slog.LevelDebug, "failed to read client config",
			slog.String("config", clientConfigName),
			slog.Any("error", err),
		)
	case len(clientConfig) > 0:
		logger.LogAttrs(
			ctx, slog.LevelDebug, "applying client config from CCD",
			slog.String("config", clientConfigName),
			slog.Any("content", clientConfig),
		)
	default:
		logger.LogAttrs(
			ctx, slog.LevelInfo, "no client config found in CCD",
			slog.String("config", clientConfigName),
		)
	}
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
		logger.LogAttrs(
			ctx, slog.LevelWarn, "failed to deny client",
			slog.Any("error", err),
		)
	}
}

func (c *Client) KillClient(ctx context.Context, logger *slog.Logger, client state.ClientIdentifier) error {
	logger.LogAttrs(ctx, slog.LevelInfo, fmt.Sprintf("kill OpenVPN client cid %d", client.CID))

	resp, err := c.SendCommandf(ctx, "client-kill %d", client.CID)
	if err != nil {
		return fmt.Errorf("kill OpenVPN client cid %d: %w", client.CID, err)
	}

	// OpenVPN returns this exact response when its CID lookup finds no active
	// client. Match it narrowly so transport and other management errors remain
	// fatal. See management_kill_by_cid in OpenVPN's src/openvpn/multi.c.
	if strings.TrimSuffix(resp, "\r\n") == clientKillFailedResponse {
		return fmt.Errorf("kill OpenVPN client cid %d: %w: %s", client.CID, connection.ErrClientNotFound, resp)
	}

	if strings.HasPrefix(resp, "ERROR:") {
		return fmt.Errorf("kill OpenVPN client cid %d: %w: %s", client.CID, ErrErrorResponse, resp)
	}

	return nil
}

func (c *Client) readClientConfig(username string) ([]string, error) {
	if !c.conf.OpenVPN.ClientConfig.Enabled || c.conf.OpenVPN.ClientConfig.Path.IsEmpty() || len(username) == 0 {
		return make([]string, 0, 1), nil
	}

	clientConfigPath := username + ".conf"
	if !fs.ValidPath(clientConfigPath) {
		return nil, fmt.Errorf("invalid client config path %q", clientConfigPath)
	}

	clientConfigFile, err := c.conf.OpenVPN.ClientConfig.Path.Open(clientConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open client config file: %w", err)
	}
	defer clientConfigFile.Close()

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
