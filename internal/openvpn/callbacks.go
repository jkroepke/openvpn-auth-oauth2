package openvpn

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"strings"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
)

func (c *Client) AcceptClient(logger *slog.Logger, client state.ClientIdentifier, username string) {
	logger.Info(fmt.Sprintf("accept OpenVPN client cid %d, kid %d", client.CID, client.KID))

	var (
		ccdConfigs []string
		err        error
	)

	if c.conf.OpenVpn.AuthTokenUser && client.UsernameIsDefined == 0 {
		tokenUsername := base64.StdEncoding.EncodeToString([]byte(username))
		ccdConfigs = append(ccdConfigs, fmt.Sprintf(`push "auth-token-user %s"`, tokenUsername))
	}

	if c.conf.OpenVpn.CCD.Enabled && c.ccdFS != nil {
		ccdConfig, err := c.getCCDConfig(client.CommonName)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				logger.Warn(err.Error())
				c.DenyClient(logger, client, "internal error")

				return
			}
		} else {
			ccdConfigs = append(ccdConfigs, ccdConfig...)
		}
	}

	if len(ccdConfigs) > 0 {
		_, err = c.SendCommandf("client-auth %d %d\r\n%s\r\nEND", client.CID, client.KID, strings.Join(ccdConfigs, "\r\n"))
	} else {
		_, err = c.SendCommandf("client-auth-nt %d %d", client.CID, client.KID)
	}

	if err != nil {
		logger.Warn(err.Error())
	}
}

func (c *Client) DenyClient(logger *slog.Logger, client state.ClientIdentifier, reason string) {
	logger.Info(fmt.Sprintf("deny OpenVPN client cid %d, kid %d", client.CID, client.KID))

	_, err := c.SendCommandf(`client-deny %d %d "%s"`, client.CID, client.KID, reason)
	if err != nil {
		logger.Warn(err.Error())
	}
}

func (c *Client) getCCDConfig(commonName string) ([]string, error) {
	fileName := commonName + ".conf"

	file, err := c.ccdFS.Open(fileName)
	if err != nil {
		return nil, fmt.Errorf("failed to open client config file %s: %w", fileName, err)
	}

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read client config file %s: %w", fileName, err)
	}

	ccdConfig := strings.Split(string(data), "\n")

	for i := range ccdConfig {
		ccdConfig[i] = strings.TrimSpace(ccdConfig[i])
	}

	return ccdConfig, nil
}
