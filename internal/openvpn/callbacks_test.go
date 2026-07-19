package openvpn_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"net/url"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config/types"
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

func TestAcceptClientEnforcesUniqueUser(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	conf := config.Defaults
	conf.OAuth2.Refresh.ValidateUser = false
	conf.OpenVPN.EnforceUniqueUser = true
	conf.OpenVPN.OverrideUsername = true

	suite := testsuite.New(&conf)
	errOpenVPNClientCh := suite.SetupManagementEnvironment(ctx, t, nil)
	openVPNClient := suite.GetOpenVPNClient()

	suite.ExpectVersionAndReleaseHold(t)

	acceptDone := make(chan error, 1)
	go func() {
		acceptDone <- openVPNClient.AcceptClient(
			ctx,
			suite.GetLogger(),
			state.ClientIdentifier{CID: 10, KID: 2},
			"alice",
		)
	}()

	suite.ExpectMessage(t, "status 3")
	suite.SendMessagef(
		t,
		"HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\tVirtual IPv6 Address\t"+
			"Bytes Received\tBytes Sent\tConnected Since\tConnected Since (time_t)\tUsername\tClient ID\tPeer ID\tData Channel Cipher\r\n"+
			"CLIENT_LIST\tclient\t127.0.0.1:1194\t10.8.0.2\t\t1\t2\tnow\t1\talice\t7\t0\tAES-256-GCM\r\n"+
			"CLIENT_LIST\tclient\t127.0.0.1:1194\t10.8.0.3\t\t1\t2\tnow\t1\tbob\t8\t0\tAES-256-GCM\r\n"+
			"CLIENT_LIST\tclient\t127.0.0.1:1194\t10.8.0.4\t\t1\t2\tnow\t1\talice\t10\t0\tAES-256-GCM\r\n"+
			"CLIENT_LIST\tclient\t127.0.0.1:1194\t10.8.0.5\t\t1\t2\tnow\t1\talice\t12\t0\tAES-256-GCM\r\nEND",
	)

	suite.ExpectMessage(t, "client-kill 7")
	suite.SendMessagef(t, "SUCCESS: client-kill command succeeded")
	suite.ExpectMessage(t, "client-kill 12")
	suite.SendMessagef(t, "ERROR: client-kill command failed")
	suite.ExpectMessage(t, "client-auth 10 2\r\noverride-username \"alice\"\r\nEND")
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

func TestAcceptClientFailsClosedWhenStatusFails(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	conf := config.Defaults
	conf.OpenVPN.EnforceUniqueUser = true
	conf.OpenVPN.OverrideUsername = true

	suite := testsuite.New(&conf)
	errOpenVPNClientCh := suite.SetupManagementEnvironment(ctx, t, nil)
	openVPNClient := suite.GetOpenVPNClient()

	suite.ExpectVersionAndReleaseHold(t)

	acceptDone := make(chan error, 1)
	go func() {
		acceptDone <- openVPNClient.AcceptClient(
			ctx,
			suite.GetLogger(),
			state.ClientIdentifier{CID: 10, KID: 2},
			"alice",
		)
	}()

	suite.ExpectMessage(t, "status 3")
	suite.SendMessagef(t, "ERROR: status command failed")

	select {
	case err := <-acceptDone:
		require.ErrorContains(t, err, "query OpenVPN status")
	case <-time.After(time.Second):
		t.Fatalf("timeout waiting for AcceptClient. Logs:\n\n%s", suite.Logs())
	}

	_, err := readOpenVPNManagementLine(t, suite, 100*time.Millisecond)
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)

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

func TestAcceptClientSerializesSessionReplacement(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	conf := config.Defaults
	conf.OpenVPN.EnforceUniqueUser = true
	conf.OpenVPN.OverrideUsername = true

	suite := testsuite.New(&conf)
	errOpenVPNClientCh := suite.SetupManagementEnvironment(ctx, t, nil)
	openVPNClient := suite.GetOpenVPNClient()

	suite.ExpectVersionAndReleaseHold(t)

	firstDone := make(chan error, 1)
	go func() {
		firstDone <- openVPNClient.AcceptClient(ctx, suite.GetLogger(), state.ClientIdentifier{CID: 1, KID: 1}, "alice")
	}()

	suite.ExpectMessage(t, "status 3")

	secondDone := make(chan error, 1)
	go func() {
		secondDone <- openVPNClient.AcceptClient(ctx, suite.GetLogger(), state.ClientIdentifier{CID: 2, KID: 1}, "alice")
	}()

	_, err := readOpenVPNManagementLine(t, suite, 100*time.Millisecond)
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)

	statusHeader := "HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\tVirtual IPv6 Address\t" +
		"Bytes Received\tBytes Sent\tConnected Since\tConnected Since (time_t)\tUsername\tClient ID\tPeer ID\tData Channel Cipher"
	suite.SendMessagef(t, statusHeader+"\r\nEND")
	suite.ExpectMessage(t, "client-auth 1 1\r\noverride-username \"alice\"\r\nEND")
	suite.SendMessagef(t, "SUCCESS: client-auth command succeeded")

	select {
	case err := <-firstDone:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatalf("timeout waiting for first AcceptClient. Logs:\n\n%s", suite.Logs())
	}

	suite.ExpectMessage(t, "status 3")
	suite.SendMessagef(
		t,
		statusHeader+"\r\n"+
			"CLIENT_LIST\tclient\t127.0.0.1:1194\t10.8.0.2\t\t1\t2\tnow\t1\talice\t1\t0\tAES-256-GCM\r\nEND",
	)
	suite.ExpectMessage(t, "client-kill 1")
	suite.SendMessagef(t, "SUCCESS: client-kill command succeeded")
	suite.ExpectMessage(t, "client-auth 2 1\r\noverride-username \"alice\"\r\nEND")
	suite.SendMessagef(t, "SUCCESS: client-auth command succeeded")

	select {
	case err := <-secondDone:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatalf("timeout waiting for second AcceptClient. Logs:\n\n%s", suite.Logs())
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
