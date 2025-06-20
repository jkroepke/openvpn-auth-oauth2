package testutils

import (
	"log/slog"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
)

// FakeOpenVPNClient implements the parts of the OpenVPN client interface used
// in tests. It does not perform any actions.
type FakeOpenVPNClient struct{}

// NewFakeOpenVPNClient returns a FakeOpenVPNClient.
func NewFakeOpenVPNClient() FakeOpenVPNClient {
	return FakeOpenVPNClient{}
}

// AcceptClient is a no-op implementation of the real method.
func (FakeOpenVPNClient) AcceptClient(_ *slog.Logger, _ state.ClientIdentifier, _ bool, _ string) {}

// DenyClient is a no-op implementation of the real method.
func (FakeOpenVPNClient) DenyClient(_ *slog.Logger, _ state.ClientIdentifier, _ string) {}
