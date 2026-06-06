package openvpn_test

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/config/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/test/testsuite"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/tokenstorage"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils/testutils"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/nettest"
)

func TestAcceptClientClosesClientConfigFile(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	logger := testsuite.NewTestLogger()
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

	managementInterface, err := nettest.NewLocalListener("tcp")
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, managementInterface.Close())
	})

	conf.OpenVPN.Addr = types.URL{URL: &url.URL{Scheme: managementInterface.Addr().Network(), Host: managementInterface.Addr().String()}}

	tokenStorage := tokenstorage.NewInMemory(testsuite.Secret, time.Hour)
	_, openVPNClient := testutils.SetupOpenVPNOAuth2Clients(ctx, t, conf, logger.Logger, http.DefaultClient, tokenStorage)

	managementInterfaceConn, errOpenVPNClientCh, err := testutils.ConnectToManagementInterface(t, managementInterface, openVPNClient)
	require.NoError(t, err)

	reader := bufio.NewReader(managementInterfaceConn)
	testutils.ExpectVersionAndReleaseHold(t, managementInterfaceConn, reader)

	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)

		openVPNClient.AcceptClient(ctx, logger.Logger, state.ClientIdentifier{CID: 1, KID: 2}, "user", "client")
	}()

	require.Equal(t, "client-auth 1 2", testutils.ReadLine(t, managementInterfaceConn, reader))
	require.True(t, file.closed.Load())
	require.Equal(t, "push route", testutils.ReadLine(t, managementInterfaceConn, reader))
	require.Equal(t, "END", testutils.ReadLine(t, managementInterfaceConn, reader))

	testutils.SendMessagef(t, managementInterfaceConn, "SUCCESS: client-auth command succeeded")

	select {
	case <-acceptDone:
	case <-time.After(time.Second):
		t.Fatalf("timeout waiting for AcceptClient. Logs:\n\n%s", logger.String())
	}

	require.NoError(t, managementInterfaceConn.Close())

	select {
	case err := <-errOpenVPNClientCh:
		if err != nil && !errors.Is(err, io.EOF) {
			require.NoError(t, err)
		}
	case <-time.After(time.Second):
		t.Fatalf("timeout waiting for connection to close. Logs:\n\n%s", logger.String())
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
