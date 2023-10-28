//go:build linux

package main

import "C"
import (
	"fmt"
	"log/slog"
	"os"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
)

func (p *PluginHandle) AcceptClient(logger *slog.Logger, client state.ClientIdentifier) {
	p.writeToAuthFile(logger, client, "1")
}

func (p *PluginHandle) AcceptClientWithToken(logger *slog.Logger, client state.ClientIdentifier, _ string) {
	p.writeToAuthFile(logger, client, "1")
}

func (p *PluginHandle) DenyClient(logger *slog.Logger, client state.ClientIdentifier, reason string) {
	if err := os.WriteFile(client.AuthFailedReasonFile, []byte(reason), 0600); err != nil {
		logger.Error(fmt.Errorf("write to file %s: %w", client.AuthFailedReasonFile, err).Error())
	}
	p.writeToAuthFile(logger, client, "0")
}

func (p *PluginHandle) writeToAuthFile(logger *slog.Logger, client state.ClientIdentifier, auth string) {
	if err := os.WriteFile(client.AuthControlFile, []byte(auth), 0600); err != nil {
		logger.Error(fmt.Errorf("write to file %s: %w", client.AuthFailedReasonFile, err).Error())
	}
}
