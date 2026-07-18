package openvpn_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config/types"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/openvpn"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/openvpn/connection"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/test/testsuite"
	"github.com/stretchr/testify/require"
)

func TestAcceptClientClosesClientConfigFile(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	file := &closeTrackingFile{Reader: bytes.NewReader([]byte("push route\n"))}
	conf := config.Config{
		HTTP: config.HTTP{
			BaseURL: types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
			Secret:  testsuite.Secret,
		},
		OpenVPN: config.OpenVPN{
			Bypass:         config.OpenVPNBypass{CommonNames: make(types.RegexpSlice, 0)},
			CommandTimeout: time.Millisecond * 300,
			ClientConfig: config.OpenVPNConfig{
				Enabled: true,
				Path:    types.FS{FS: singleFileFS{file: file}},
			},
		},
	}

	suite := testsuite.New(&conf)
	errOpenVPNClientCh := suite.SetupManagementEnvironment(ctx, t, nil)
	openVPNClient := suite.GetOpenVPNClient()

	suite.ExpectVersionAndReleaseHold(t)

	acceptDone := make(chan error, 1)
	go func() {
		acceptDone <- openVPNClient.AcceptClient(ctx, suite.GetLogger(), state.ClientIdentifier{CID: 1, KID: 2}, "user", "client")
	}()

	require.Equal(t, "client-auth 1 2", suite.ReadLine(t))
	require.True(t, file.closed.Load())
	require.Equal(t, "push route", suite.ReadLine(t))
	require.Equal(t, "END", suite.ReadLine(t))

	suite.SendMessagef(t, "SUCCESS: client-auth command succeeded")

	select {
	case err := <-acceptDone:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatalf("timeout waiting for AcceptClient. Logs:\n\n%s", suite.Logs())
	}

	require.NoError(t, suite.GetManagementInterfaceConn().Close())

	select {
	case err := <-errOpenVPNClientCh:
		if err != nil && !errors.Is(err, io.EOF) {
			require.NoError(t, err)
		}
	case <-time.After(time.Second):
		t.Fatalf("timeout waiting for connection to close. Logs:\n\n%s", suite.Logs())
	}
}

func TestKillClientReturnsOpenVPNErrorResponse(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		response string
		target   error
	}{
		{
			name:     "client does not exist",
			response: "ERROR: client-kill command failed",
			target:   connection.ErrClientNotFound,
		},
		{
			name:     "other OpenVPN error",
			response: "ERROR: command not allowed",
			target:   openvpn.ErrErrorResponse,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(cancel)

			conf := config.Defaults
			suite := testsuite.New(&conf)
			errOpenVPNClientCh := suite.SetupManagementEnvironment(ctx, t, nil)
			openVPNClient := suite.GetOpenVPNClient()

			suite.ExpectVersionAndReleaseHold(t)

			killErrCh := make(chan error, 1)
			go func() {
				killErrCh <- openVPNClient.KillClient(ctx, suite.GetLogger(), state.ClientIdentifier{CID: 1})
			}()

			suite.ExpectMessage(t, "client-kill 1")
			suite.SendMessagef(t, "%s", tc.response)

			select {
			case err := <-killErrCh:
				require.ErrorIs(t, err, tc.target)
			case <-time.After(time.Second):
				t.Fatalf("timeout waiting for KillClient. Logs:\n\n%s", suite.Logs())
			}

			require.NoError(t, suite.GetManagementInterfaceConn().Close())

			select {
			case err := <-errOpenVPNClientCh:
				if err != nil && !errors.Is(err, io.EOF) {
					require.NoError(t, err)
				}
			case <-time.After(time.Second):
				t.Fatalf("timeout waiting for connection to close. Logs:\n\n%s", suite.Logs())
			}
		})
	}
}

type singleFileFS struct {
	file fs.File
}

func (f singleFileFS) Open(string) (fs.File, error) {
	return f.file, nil
}

type closeTrackingFile struct {
	io.Reader

	closed atomic.Bool
}

func (f *closeTrackingFile) Stat() (fs.FileInfo, error) {
	return fileInfo{}, nil
}

func (f *closeTrackingFile) Close() error {
	f.closed.Store(true)

	return nil
}

type fileInfo struct{}

func (fileInfo) Name() string {
	return "client.conf"
}

func (fileInfo) Size() int64 {
	return 0
}

func (fileInfo) Mode() fs.FileMode {
	return 0
}

func (fileInfo) ModTime() time.Time {
	return time.Time{}
}

func (fileInfo) IsDir() bool {
	return false
}

func (fileInfo) Sys() any {
	return nil
}
