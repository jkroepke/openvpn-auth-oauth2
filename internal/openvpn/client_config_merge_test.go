//nolint:testpackage
package openvpn

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"testing"
	"testing/fstest"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/config/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/stretchr/testify/require"
)

func TestLoadClientConfigMerge(t *testing.T) {
	t.Parallel()

	conf := config.Defaults
	conf.OpenVPN.OverrideUsername = true
	conf.OpenVPN.ClientConfig.Enabled = true
	conf.OpenVPN.ClientConfig.Strategy = config.OpenVPNConfigStrategyMerge
	conf.OpenVPN.ClientConfig.Path = types.FS{
		FS: fstest.MapFS{
			"base.conf": {
				Data: []byte("push \"route 10.0.0.0 255.0.0.0\"\npush \"route 10.1.0.0 255.255.0.0\"\n"),
			},
			"admin.conf": {
				Data: []byte("push \"route 10.1.0.0 255.255.0.0\"\npush \"route 10.2.0.0 255.255.0.0\"\n"),
			},
			"alice.conf": {
				Data: []byte("push \"route 10.3.0.0 255.255.0.0\"\n"),
			},
		},
	}

	client := Client{conf: &conf}
	clientConfig, err := client.loadClientConfig(
		context.Background(),
		slog.New(slog.DiscardHandler),
		state.ClientIdentifier{},
		[]string{"base", "admin", "base", "missing", "alice"},
		"alice",
	)

	require.NoError(t, err)
	require.Equal(t, []string{
		`push "route 10.0.0.0 255.0.0.0"`,
		`push "route 10.1.0.0 255.255.0.0"`,
		`push "route 10.2.0.0 255.255.0.0"`,
		`push "route 10.3.0.0 255.255.0.0"`,
		`override-username "alice"`,
	}, clientConfig)
}

func TestLoadClientConfigDisabledDoesNotReadDefault(t *testing.T) {
	t.Parallel()

	conf := config.Defaults
	conf.OAuth2.Refresh.ValidateUser = false
	conf.OpenVPN.ClientConfig.Enabled = false
	conf.OpenVPN.ClientConfig.Path = types.FS{FS: failOpenFS{}}

	client := Client{conf: &conf}
	clientConfig, err := client.loadClientConfig(
		context.Background(),
		slog.New(slog.DiscardHandler),
		state.ClientIdentifier{},
		nil,
		"alice",
	)

	require.NoError(t, err)
	require.Empty(t, clientConfig)
}

func TestLoadClientConfigEmptyListFallsBackToDefault(t *testing.T) {
	t.Parallel()

	conf := config.Defaults
	conf.OAuth2.Refresh.ValidateUser = false
	conf.OpenVPN.ClientConfig.Enabled = true
	conf.OpenVPN.ClientConfig.Strategy = config.OpenVPNConfigStrategyMerge
	conf.OpenVPN.ClientConfig.Path = types.FS{
		FS: fstest.MapFS{
			"DEFAULT.conf": {
				Data: []byte("push \"route 10.0.0.0 255.0.0.0\"\n"),
			},
		},
	}

	client := Client{conf: &conf}
	clientConfig, err := client.loadClientConfig(
		context.Background(),
		slog.New(slog.DiscardHandler),
		state.ClientIdentifier{},
		nil,
		"alice",
	)

	require.NoError(t, err)
	require.Equal(t, []string{`push "route 10.0.0.0 255.0.0.0"`}, clientConfig)
}

func TestLoadClientConfigMissingDoesNotFallBackToDefault(t *testing.T) {
	t.Parallel()

	conf := config.Defaults
	conf.OAuth2.Refresh.ValidateUser = false
	conf.OpenVPN.ClientConfig.Enabled = true
	conf.OpenVPN.ClientConfig.Strategy = config.OpenVPNConfigStrategyMerge
	conf.OpenVPN.ClientConfig.Path = types.FS{
		FS: fstest.MapFS{
			"DEFAULT.conf": {
				Data: []byte("push \"route 10.0.0.0 255.0.0.0\"\n"),
			},
		},
	}

	client := Client{conf: &conf}
	clientConfig, err := client.loadClientConfig(
		context.Background(),
		slog.New(slog.DiscardHandler),
		state.ClientIdentifier{},
		[]string{"missing"},
		"alice",
	)

	require.NoError(t, err)
	require.Empty(t, clientConfig)
}

func TestLoadClientConfigMissingStrict(t *testing.T) {
	t.Parallel()

	conf := config.Defaults
	conf.OpenVPN.ClientConfig.Enabled = true
	conf.OpenVPN.ClientConfig.IgnoreNotFound = false
	conf.OpenVPN.ClientConfig.Strategy = config.OpenVPNConfigStrategyMerge
	conf.OpenVPN.ClientConfig.Path = types.FS{FS: fstest.MapFS{}}

	client := Client{conf: &conf}
	clientConfig, err := client.loadClientConfig(
		context.Background(),
		slog.New(slog.DiscardHandler),
		state.ClientIdentifier{},
		[]string{"missing"},
		"alice",
	)

	require.Error(t, err)
	require.Nil(t, clientConfig)
}

type failOpenFS struct{}

func (failOpenFS) Open(string) (fs.File, error) {
	return nil, errors.New("unexpected client config read")
}
