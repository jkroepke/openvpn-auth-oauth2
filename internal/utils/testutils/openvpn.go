package testutils

import (
	"log/slog"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
)

type FakeOpenVPNClient struct{}

func NewFakeOpenVPNClient() FakeOpenVPNClient {
	return FakeOpenVPNClient{}
}

func (FakeOpenVPNClient) AcceptClient(_ *slog.Logger, _ state.ClientIdentifier, _ bool, _ string) {}

func (FakeOpenVPNClient) DenyClient(_ *slog.Logger, _ state.ClientIdentifier, _ string) {}
