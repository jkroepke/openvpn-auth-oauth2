//go:build (darwin || linux || openbsd || freebsd) && cgo

package internal_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/containerd/errdefs"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config/types"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/httphandler"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/openvpn"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/test/testsuite"
	"github.com/moby/moby/api/types/container"
	dockerclient "github.com/moby/moby/client"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"golang.org/x/net/nettest"
)

const (
	uniqueUserITImage = "testcontainers/openvpn-auth-oauth2-unique-user-it:latest"

	uniqueUserServerEntrypoint = `#!/bin/sh
set -eu

if [ ! -f /etc/openvpn/pki/ca.crt ]; then
  /usr/share/easy-rsa/easyrsa init-pki
  /usr/share/easy-rsa/easyrsa build-ca nopass
  /usr/share/easy-rsa/easyrsa build-server-full server nopass
  /usr/share/easy-rsa/easyrsa build-client-full shared-client nopass
fi

printf password > /etc/openvpn/password.txt

cat > /etc/openvpn/openvpn.conf <<EOF
dev tun0
server 100.64.0.0 255.255.255.0
topology subnet
proto udp
port 1194

ca /etc/openvpn/pki/ca.crt
key /etc/openvpn/pki/private/server.key
cert /etc/openvpn/pki/issued/server.crt
dh none
tls-cert-profile preferred
verify-client-cert none

management 0.0.0.0 8081 /etc/openvpn/password.txt
management-client-auth
management-hold

auth-user-pass-optional
duplicate-cn
disable-dco
explicit-exit-notify
keepalive 10 60
persist-key
persist-tun
reneg-sec 600
verb 3
EOF

for management_port in 8082 8083; do
  cat > "/etc/openvpn/client-$management_port.ovpn" <<EOF
client
dev tun
setenv IV_SSO webauth
nobind
remote 127.0.0.1 1194 udp4
remote-cert-tls server
connect-retry-max 2
tls-cert-profile preferred
persist-key
persist-tun
disable-dco
reneg-sec 0
verb 3
management 0.0.0.0 $management_port
management-hold
<key>
$(cat /etc/openvpn/pki/private/shared-client.key)
</key>
<cert>
$(openssl x509 -in /etc/openvpn/pki/issued/shared-client.crt)
</cert>
<ca>
$(cat /etc/openvpn/pki/ca.crt)
</ca>
EOF
done

exec openvpn --config /etc/openvpn/openvpn.conf --tmp-dir /tmp/
`
)

type managedOpenVPNITClient struct {
	container  testcontainers.Container
	connection net.Conn
	management *testsuite.Conn
}

func TestITEnforceUniqueUser(t *testing.T) {
	t.Parallel()

	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	if os.Getenv("CI") == "" && os.Getenv("OPENVPN_IT_TEST") != "1" {
		t.Skip("skipping integration test, OPENVPN_IT_TEST is not set")
	}

	testcontainers.SkipIfProviderIsNotHealthy(t)

	volumeName := fmt.Sprintf("openvpn-auth-oauth2-unique-user-it-%d", time.Now().UnixNano())
	setupUniqueUserITDockerCleanup(t, volumeName)
	server := startUniqueUserITServer(t, volumeName)
	client1 := startUniqueUserITClient(t, server, volumeName, 8082)
	client2 := startUniqueUserITClient(t, server, volumeName, 8083)

	suite, httpServer, openVPNClient, connectErrCh := startUniqueUserITService(t, server)
	t.Cleanup(func() {
		openVPNClient.Shutdown(context.Background())

		select {
		case err := <-connectErrCh:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Errorf("OpenVPN management client stopped with an error: %v\n%s", err, suite.Logs())
			}
		case <-time.After(5 * time.Second):
			t.Errorf("timeout waiting for OpenVPN management client shutdown\n%s", suite.Logs())
		}
	})

	authenticateUniqueUserITClient(t, client1, httpServer, server)
	authenticateUniqueUserITClient(t, client2, httpServer, server)

	waitForOpenVPNITMessage(t, client1, server, func(line string) bool {
		return strings.HasPrefix(line, ">HOLD:Waiting for hold release:")
	})
}

func setupUniqueUserITDockerCleanup(t *testing.T, volumeName string) {
	t.Helper()

	dockerClient, err := testcontainers.NewDockerClientWithOpts(t.Context())
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = dockerClient.Close()
	})
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		_, err := dockerClient.VolumeRemove(ctx, volumeName, dockerclient.VolumeRemoveOptions{Force: true})
		if err != nil && !errdefs.IsNotFound(err) {
			t.Errorf("remove Docker volume %s: %v", volumeName, err)
		}
	})
}

func startUniqueUserITServer(t *testing.T, volumeName string) testcontainers.Container {
	t.Helper()

	server, err := testcontainers.Run(
		t.Context(),
		"",
		testcontainers.WithDockerfile(testcontainers.FromDockerfile{
			Context:    "../",
			Dockerfile: "./tests/Dockerfile",
			Repo:       "testcontainers/openvpn-auth-oauth2-unique-user-it",
			Tag:        "latest",
			KeepImage:  true,
		}),
		testcontainers.WithExposedPorts("8081/tcp", "8082/tcp", "8083/tcp"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("MANAGEMENT: TCP Socket listening").WithStartupTimeout(2*time.Minute),
		),
		testcontainers.WithLabels(map[string]string{"testcontainers": "true"}),
		testcontainers.WithMounts(testcontainers.ContainerMount{
			Source: testcontainers.GenericVolumeMountSource{Name: volumeName},
			Target: "/etc/openvpn",
		}),
		testcontainers.WithFiles(testcontainers.ContainerFile{
			Reader:            strings.NewReader(uniqueUserServerEntrypoint),
			ContainerFilePath: "/entrypoint.sh",
			FileMode:          0o755,
		}),
		withOpenVPNITContainerPrivileges(""),
		testcontainers.WithEntrypoint("/entrypoint.sh"),
	)
	if server != nil {
		testcontainers.CleanupContainer(t, server)
	}

	require.NoError(t, err, openVPNITContainerLogs(t, server))
	require.NotNil(t, server)

	return server
}

func startUniqueUserITClient(
	t *testing.T,
	server testcontainers.Container,
	volumeName string,
	managementPort int,
) managedOpenVPNITClient {
	t.Helper()

	clientContainer, err := testcontainers.Run(
		t.Context(),
		uniqueUserITImage,
		testcontainers.WithLabels(map[string]string{"testcontainers": "true"}),
		testcontainers.WithMounts(testcontainers.ContainerMount{
			Source: testcontainers.GenericVolumeMountSource{Name: volumeName},
			Target: "/etc/openvpn",
		}),
		withOpenVPNITContainerPrivileges(server.GetContainerID()),
		testcontainers.WithWaitStrategy(
			wait.ForLog("Need hold release from management interface").WithStartupTimeout(30*time.Second),
		),
		testcontainers.WithEntrypoint("openvpn"),
		testcontainers.WithEntrypointArgs(
			"--config",
			fmt.Sprintf("/etc/openvpn/client-%d.ovpn", managementPort),
			"--echo",
			"off",
		),
	)
	if clientContainer != nil {
		testcontainers.CleanupContainer(t, clientContainer)
	}

	require.NoError(t, err, openVPNITContainerLogs(t, server, clientContainer))
	require.NotNil(t, clientContainer)

	managementEndpoint, err := server.PortEndpoint(t.Context(), strconv.Itoa(managementPort), "tcp")
	require.NoError(t, err)

	var dialer net.Dialer

	managementConnection, err := dialer.DialContext(
		t.Context(),
		"tcp",
		strings.TrimPrefix(managementEndpoint, "tcp://"),
	)
	require.NoError(t, err, openVPNITContainerLogs(t, server, clientContainer))
	t.Cleanup(func() {
		_ = managementConnection.Close()
	})

	management := testsuite.NewConn(managementConnection).WithLogs(func() string {
		return openVPNITContainerLogs(t, server, clientContainer)
	})
	require.Regexp(
		t,
		`^>INFO:OpenVPN Management Interface Version [5-9][0-9]* -- type 'help' for more info$`,
		management.ReadLine(t),
	)
	management.ExpectMessage(t, ">HOLD:Waiting for hold release:0")
	management.SendAndExpectMessage(t, "state on", "SUCCESS: real-time state notification set to ON")

	return managedOpenVPNITClient{
		container:  clientContainer,
		connection: managementConnection,
		management: management,
	}
}

func withOpenVPNITContainerPrivileges(networkContainerID string) testcontainers.CustomizeRequestOption {
	return testcontainers.WithHostConfigModifier(func(hostConfig *container.HostConfig) {
		hostConfig.Binds = []string{"/dev/net/tun:/dev/net/tun"}

		hostConfig.CapAdd = []string{"NET_ADMIN"}
		if networkContainerID != "" {
			hostConfig.NetworkMode = container.NetworkMode("container:" + networkContainerID)
		}
	})
}

func startUniqueUserITService(
	t *testing.T,
	server testcontainers.Container,
) (*testsuite.Suite, *httptest.Server, *openvpn.Client, <-chan error) {
	t.Helper()

	clientListener, err := nettest.NewLocalListener("tcp")
	require.NoError(t, err)

	managementEndpoint, err := server.PortEndpoint(t.Context(), "8081", "tcp")
	require.NoError(t, err)

	conf := config.Defaults
	conf.OAuth2.OpenVPNUsername = "oauth2TokenClaims." + testsuite.SubjectClaim
	conf.OpenVPN.Addr = types.URL{
		URL: &url.URL{Scheme: "tcp", Host: strings.TrimPrefix(managementEndpoint, "tcp://")},
	}
	conf.OpenVPN.Password = testsuite.Password
	conf.OpenVPN.EnforceUniqueUser = true
	conf.OpenVPN.OverrideUsername = true

	suite := testsuite.New(&conf)
	suite.SetupOIDCServer(t, clientListener, nil)
	oAuth2Client, openVPNClient := suite.SetupOpenVPNOAuth2Clients(t.Context(), t, nil)

	connectErrCh := make(chan error, 1)
	go func() {
		connectErrCh <- openVPNClient.Connect(t.Context())
	}()

	httpServer := httptest.NewUnstartedServer(httphandler.New(suite.GetConfig(), oAuth2Client))
	require.NoError(t, httpServer.Listener.Close())

	httpServer.Listener = clientListener
	httpServer.Start()
	t.Cleanup(httpServer.Close)

	return suite, httpServer, openVPNClient, connectErrCh
}

func authenticateUniqueUserITClient(
	t *testing.T,
	client managedOpenVPNITClient,
	httpServer *httptest.Server,
	server testcontainers.Container,
) {
	t.Helper()

	client.management.SendAndExpectMessage(t, "hold release", "SUCCESS: hold release succeeded")

	webAuthMessage := waitForOpenVPNITMessage(t, client, server, func(line string) bool {
		return strings.HasPrefix(line, ">INFOMSG:WEB_AUTH::")
	})
	webAuthURL := strings.TrimSpace(strings.TrimPrefix(webAuthMessage, ">INFOMSG:WEB_AUTH::"))

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	httpClient := httpServer.Client()
	httpClient.Jar = jar

	resp, _, err := testsuite.DoHTTPRequest(t, httpClient, "", http.MethodGet, webAuthURL, nil, http.NoBody) //nolint:bodyclose
	require.NoError(t, err, openVPNITContainerLogs(t, server, client.container))
	require.Equal(t, http.StatusOK, resp.StatusCode, openVPNITContainerLogs(t, server, client.container))

	waitForOpenVPNITMessage(t, client, server, func(line string) bool {
		return strings.HasPrefix(line, ">STATE:") && strings.Contains(line, ",CONNECTED,")
	})
}

func waitForOpenVPNITMessage(
	t *testing.T,
	client managedOpenVPNITClient,
	server testcontainers.Container,
	matches func(string) bool,
) string {
	t.Helper()

	require.NoError(t, client.connection.SetReadDeadline(time.Now().Add(30*time.Second)))

	var received []string

	for {
		line, err := client.management.Reader().ReadString('\n')
		if err != nil {
			t.Fatalf(
				"read OpenVPN client management event: %v\nreceived:\n%s\n%s",
				err,
				strings.Join(received, "\n"),
				openVPNITContainerLogs(t, server, client.container),
			)
		}

		line = strings.TrimSpace(line)
		received = append(received, line)

		if matches(line) {
			return line
		}
	}
}

func openVPNITContainerLogs(t *testing.T, containers ...testcontainers.Container) string {
	t.Helper()

	var logs strings.Builder

	for _, testContainer := range containers {
		if testContainer == nil {
			continue
		}

		logReader, err := testContainer.Logs(t.Context())
		if err != nil {
			_, _ = fmt.Fprintf(&logs, "read container %s logs: %v\n", testContainer.GetContainerID(), err)

			continue
		}

		containerLogs, readErr := io.ReadAll(logReader)
		_ = logReader.Close()

		_, _ = fmt.Fprintf(&logs, "container %s:\n%s\n", testContainer.GetContainerID(), containerLogs)
		if readErr != nil {
			_, _ = fmt.Fprintf(&logs, "read container log stream: %v\n", readErr)
		}
	}

	return logs.String()
}
